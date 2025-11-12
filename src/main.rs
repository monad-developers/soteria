use anyhow::{Context, Result, anyhow};
use clap::{ArgAction, Parser};
use owo_colors::OwoColorize;
use primitive_types::U256;
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

// These strings stay short, so computing the hashes at runtime keeps things simple.
const DOMAIN_TYPE: &str = "EIP712Domain(uint256 chainId,address verifyingContract)";
const SAFE_TX_TYPE: &str = "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)";

fn main() -> Result<()> {
    let args = CliArgs::parse();
    let resolved_inputs = args.resolved_inputs();
    let mut targets = collect_targets(&resolved_inputs, args.safe_address.as_deref())?;
    if targets.is_empty() {
        println!(
            "{}",
            "No JSON files found. Provide one or more directories or files to process.".yellow()
        );
        return Ok(());
    }
    targets.sort_by(|a, b| a.path.cmp(&b.path));

    let mut mismatches = Vec::new();

    for target in targets {
        match process_file(
            &target.path,
            args.chain_id,
            args.safe_address.as_deref(),
            target.directory_safe.as_deref(),
        ) {
            Ok(report) => {
                println!("{}", report.render_line());
                if report.is_mismatch() {
                    mismatches.push(report);
                }
            }
            Err(err) => {
                let message = format!("{}\nerror\n{}", target.path.display(), err);
                println!("{}", message.red());
            }
        }
    }

    if !mismatches.is_empty() {
        let message = format!("{} mismatches detected.", mismatches.len());
        if args.ignore_error {
            println!("{}", message.yellow());
        } else {
            println!("{}", message.red());
            std::process::exit(1);
        }
    }

    Ok(())
}

#[derive(Parser, Debug)]
#[command(
    name = "soteria",
    version,
    author,
    about = "Validate Safe transaction hashes for JSON log files"
)]
struct CliArgs {
    /// Additional file or directory inputs
    #[arg(short = 'i', long = "input", alias = "dir", value_name = "PATH", action = ArgAction::Append)]
    input: Vec<PathBuf>,
    /// Positional paths to include
    #[arg(value_name = "PATH")]
    paths: Vec<PathBuf>,
    /// Chain ID for the Monad network
    #[arg(long = "chain-id", default_value_t = 143)]
    chain_id: u64,
    /// Override Safe address for all transactions
    #[arg(long = "safe-address")]
    safe_address: Option<String>,
    /// Do not fail the process when mismatches occur
    #[arg(long = "ignore-error", action = ArgAction::SetTrue)]
    ignore_error: bool,
}

impl CliArgs {
    fn resolved_inputs(&self) -> Vec<PathBuf> {
        let mut inputs = Vec::new();
        inputs.extend(self.input.iter().cloned());
        inputs.extend(self.paths.iter().cloned());
        inputs
    }
}

#[derive(Debug, Deserialize)]
struct TransactionLog {
    address_to: String,
    #[serde(default, deserialize_with = "string_or_number")]
    native_value: String,
    calldata: String,
    operation: Option<String>,
    current_nonce: u64,
    expected_hash: Option<String>,
    #[serde(default, deserialize_with = "string_or_number_opt")]
    safe_tx_gas: Option<String>,
    #[serde(default, deserialize_with = "string_or_number_opt")]
    base_gas: Option<String>,
    #[serde(default, deserialize_with = "string_or_number_opt")]
    gas_price: Option<String>,
    gas_token: Option<String>,
    refund_receiver: Option<String>,
}

#[derive(Debug)]
struct Report {
    path: PathBuf,
    computed_hash: String,
    expected_hash: Option<String>,
    matched: Option<bool>,
    safe_address_used: String,
}

#[derive(Clone, Debug)]
struct Target {
    path: PathBuf,
    directory_safe: Option<String>,
}

impl Report {
    fn render_line(&self) -> String {
        let path = self.path.display().to_string();
        let safe = format!("safe address = {}", self.safe_address_used);

        match (&self.expected_hash, self.matched) {
            (Some(_), Some(true)) => {
                let hash = format!("computed hash = {} (expected)", self.computed_hash);
                format!("{}:\n{}\n{}", path.cyan(), hash.green(), safe.magenta())
            }
            (Some(expected), Some(false)) => {
                let hash = format!("computed hash = {} (mismatch)", self.computed_hash);
                let expected_segment = format!("expected hash = {}", expected);
                format!(
                    "{}:\n{}\n{}\n{}",
                    path.cyan(),
                    hash.red(),
                    expected_segment.yellow(),
                    safe.magenta(),
                )
            }
            (Some(expected), None) => {
                let hash = format!("computed hash = {}", self.computed_hash);
                let expected_segment = format!("expected hash = {}", expected);
                format!(
                    "{}:\n{}\n{}\n{}",
                    path.cyan(),
                    hash.cyan(),
                    expected_segment.yellow(),
                    safe.magenta()
                )
            }
            (None, _) => {
                let hash = format!("computed hash = {}", self.computed_hash);
                format!(
                    "{}:\n{}\n{}\n",
                    path.cyan(),
                    hash.bright_white(),
                    safe.magenta()
                )
            }
        }
    }

    fn is_mismatch(&self) -> bool {
        matches!(self.matched, Some(false))
    }
}

fn collect_targets(inputs: &[PathBuf], safe_address: Option<&str>) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    for input in inputs {
        if input.is_dir() {
            gather_directory_targets(input, safe_address, &mut targets)?;
        } else if input.is_file() {
            if !input
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            {
                continue;
            }

            if is_empty_file(input)? {
                continue;
            }

            if is_account_config(input) {
                // Account config files are not transaction payloads.
                continue;
            }

            let directory_safe = if safe_address.is_none() {
                if let Some(parent) = input.parent() {
                    if let Some(account_config) = find_account_config(parent)? {
                        load_account_config_safe(&account_config)?
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            };

            targets.push(Target {
                path: input.clone(),
                directory_safe,
            });
        }
    }
    Ok(targets)
}

fn is_empty_file(path: &Path) -> Result<bool> {
    Ok(path.is_file() && fs::metadata(path)?.len() == 0)
}

fn process_file(
    path: &Path,
    chain_id: u64,
    safe_address: Option<&str>,
    directory_safe: Option<&str>,
) -> Result<Report> {
    let data =
        fs::read_to_string(path).with_context(|| format!("unable to read {}", path.display()))?;
    let tx: TransactionLog = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;

    let safe_address_str = safe_address
        .or(directory_safe)
        .ok_or_else(|| anyhow!("no Safe address provided"))?;

    let computed = compute_safe_tx_hash(&tx, safe_address_str, chain_id)?;
    let expected = tx.expected_hash.as_ref().map(|value| normalize_hex(value));
    let matched = expected
        .as_ref()
        .map(|expected_hash| expected_hash.eq_ignore_ascii_case(&computed));

    Ok(Report {
        path: path.to_path_buf(),
        computed_hash: computed,
        expected_hash: expected,
        matched,
        safe_address_used: normalize_hex(safe_address_str),
    })
}

fn gather_directory_targets(
    dir: &Path,
    cli_safe: Option<&str>,
    targets: &mut Vec<Target>,
) -> Result<()> {
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(dir).with_context(|| format!("cannot read directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
            && !is_empty_file(&path)?
        {
            entries.push(path);
        }
    }

    let directory_safe = if cli_safe.is_none() {
        if let Some(account_config) = entries.iter().find(|path| is_account_config(path)) {
            load_account_config_safe(account_config)?
        } else if let Some(account_config) = find_account_config(dir)? {
            load_account_config_safe(&account_config)?
        } else {
            None
        }
    } else {
        None
    };

    for path in entries {
        if is_account_config(&path) {
            continue;
        }

        targets.push(Target {
            path,
            directory_safe: directory_safe.clone(),
        });
    }

    Ok(())
}

fn is_account_config(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.eq_ignore_ascii_case("accountConfig.json"))
        .unwrap_or(false)
}

fn find_account_config(dir: &Path) -> Result<Option<PathBuf>> {
    for entry in
        fs::read_dir(dir).with_context(|| format!("cannot read directory {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && is_account_config(&path) && !is_empty_file(&path)? {
            return Ok(Some(path));
        }
    }
    Ok(None)
}

#[derive(Debug, Deserialize)]
struct AccountConfig {
    safe_address: Option<String>,
}

fn load_account_config_safe(path: &Path) -> Result<Option<String>> {
    let data =
        fs::read_to_string(path).with_context(|| format!("unable to read {}", path.display()))?;
    let config: AccountConfig = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(config.safe_address)
}

fn compute_safe_tx_hash(tx: &TransactionLog, safe_address: &str, chain_id: u64) -> Result<String> {
    let to = parse_address(&tx.address_to).context("invalid to address")?;
    let safe = parse_address(safe_address).context("invalid safe address")?;
    let value = parse_u256(&tx.native_value).context("invalid native value")?;
    let data_bytes = decode_hex(&tx.calldata).context("invalid calldata hex")?;
    let data_hash = keccak256(&data_bytes);

    let operation = parse_operation(tx.operation.as_deref())?;
    let safe_tx_gas = parse_optional_u256(tx.safe_tx_gas.as_deref())?.unwrap_or_else(U256::zero);
    let base_gas = parse_optional_u256(tx.base_gas.as_deref())?.unwrap_or_else(U256::zero);
    let gas_price = parse_optional_u256(tx.gas_price.as_deref())?.unwrap_or_else(U256::zero);
    let gas_token = tx
        .gas_token
        .as_deref()
        .map(parse_address)
        .transpose()
        .context("invalid gas token address")?
        .unwrap_or([0u8; 20]);
    let refund_receiver = tx
        .refund_receiver
        .as_deref()
        .map(parse_address)
        .transpose()
        .context("invalid refund receiver address")?
        .unwrap_or([0u8; 20]);
    let nonce = U256::from(tx.current_nonce);

    let domain_separator = build_domain_separator(chain_id, safe);
    let tx_hash_struct = build_tx_struct_hash(
        to,
        value,
        data_hash,
        operation,
        safe_tx_gas,
        base_gas,
        gas_price,
        gas_token,
        refund_receiver,
        nonce,
    );

    let mut eip_message = Vec::with_capacity(2 + 32 + 32);
    eip_message.push(0x19);
    eip_message.push(0x01);
    eip_message.extend_from_slice(&domain_separator);
    eip_message.extend_from_slice(&tx_hash_struct);

    Ok(format!("0x{}", hex::encode(keccak256(&eip_message))))
}

fn build_domain_separator(chain_id: u64, safe: [u8; 20]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(32 * 3);
    encoded.extend_from_slice(&keccak256(DOMAIN_TYPE.as_bytes()));
    encoded.extend_from_slice(&encode_u256(U256::from(chain_id)));
    encoded.extend_from_slice(&encode_address(safe));
    keccak256(&encoded)
}

fn build_tx_struct_hash(
    to: [u8; 20],
    value: U256,
    data_hash: [u8; 32],
    operation: u8,
    safe_tx_gas: U256,
    base_gas: U256,
    gas_price: U256,
    gas_token: [u8; 20],
    refund_receiver: [u8; 20],
    nonce: U256,
) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(32 * 11);
    encoded.extend_from_slice(&keccak256(SAFE_TX_TYPE.as_bytes()));
    encoded.extend_from_slice(&encode_address(to));
    encoded.extend_from_slice(&encode_u256(value));
    encoded.extend_from_slice(&data_hash);
    encoded.extend_from_slice(&encode_u8(operation));
    encoded.extend_from_slice(&encode_u256(safe_tx_gas));
    encoded.extend_from_slice(&encode_u256(base_gas));
    encoded.extend_from_slice(&encode_u256(gas_price));
    encoded.extend_from_slice(&encode_address(gas_token));
    encoded.extend_from_slice(&encode_address(refund_receiver));
    encoded.extend_from_slice(&encode_u256(nonce));
    keccak256(&encoded)
}

fn parse_operation(operation: Option<&str>) -> Result<u8> {
    match operation {
        Some(op) => {
            let lowered = op.trim().to_ascii_lowercase();
            match lowered.as_str() {
                "call" => Ok(0),
                "delegatecall" => Ok(1),
                "create" => Ok(2),
                "create2" => Ok(3),
                other => {
                    if let Ok(value) = other.parse::<u8>() {
                        Ok(value)
                    } else {
                        Err(anyhow!("unsupported operation '{}'", op))
                    }
                }
            }
        }
        None => Ok(0),
    }
}

fn parse_u256(value: &str) -> Result<U256> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed.strip_prefix("0x") {
        U256::from_str_radix(hex, 16).context("malformed hex value")
    } else {
        U256::from_dec_str(trimmed).context("malformed decimal value")
    }
}

fn parse_optional_u256(value: Option<&str>) -> Result<Option<U256>> {
    match value {
        Some(val) if !val.trim().is_empty() => parse_u256(val).map(Some),
        _ => Ok(None),
    }
}

fn parse_address(value: &str) -> Result<[u8; 20]> {
    let trimmed = value.trim();
    let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex_str.len() != 40 {
        return Err(anyhow!("address must be 20 bytes"));
    }
    let bytes = hex::decode(hex_str).context("address contains non-hex characters")?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_hex(value: &str) -> Result<Vec<u8>> {
    let trimmed = value.trim();
    let hex_str = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if hex_str.is_empty() {
        return Ok(Vec::new());
    }
    if hex_str.len() % 2 != 0 {
        return Err(anyhow!("hex string must have even length"));
    }
    hex::decode(hex_str).context("data contains non-hex characters")
}

fn encode_address(address: [u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(&address);
    out
}

fn encode_u256(value: U256) -> [u8; 32] {
    let mut out = [0u8; 32];
    value.to_big_endian(&mut out);
    out
}

fn encode_u8(value: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[31] = value;
    out
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut output = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

fn normalize_hex(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        format!("0x{}", trimmed[2..].to_ascii_lowercase())
    } else {
        format!("0x{}", trimmed.to_ascii_lowercase())
    }
}

fn string_or_number<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    use serde_json::Value;

    match Value::deserialize(deserializer)? {
        Value::String(s) => Ok(s),
        Value::Number(n) => Ok(n.to_string()),
        other => Err(Error::custom(format!("unsupported value type {other}"))),
    }
}

fn string_or_number_opt<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;
    use serde_json::Value;

    let value = Option::<Value>::deserialize(deserializer)?;
    match value {
        Some(Value::String(s)) => Ok(Some(s)),
        Some(Value::Number(n)) => Ok(Some(n.to_string())),
        Some(Value::Null) => Ok(None),
        Some(other) => Err(Error::custom(format!("unsupported value type {other}"))),
        None => Ok(None),
    }
}
