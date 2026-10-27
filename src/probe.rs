//! ICMP observations with explicit local failures. Never fabricate packet loss.
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct Probe {
    pub rtt: Option<f64>,
    pub loss: Option<f64>,
    pub status: &'static str,
    pub reason: &'static str,
}
impl Probe {
    fn unavailable(reason: &'static str) -> Self {
        Self {
            rtt: None,
            loss: None,
            status: "unavailable",
            reason,
        }
    }
}
pub fn run(target: Option<&str>) -> Probe {
    let Some(target) = target else {
        return Probe {
            rtt: None,
            loss: None,
            status: "not_configured",
            reason: "no_target",
        };
    };
    if target.is_empty() || target.starts_with('-') || target.chars().any(char::is_whitespace) {
        return Probe::unavailable("invalid_target");
    }
    let binary = if cfg!(target_os = "macos") && target.contains(':') {
        "ping6"
    } else {
        "ping"
    };
    let mut cmd = Command::new(binary);
    cmd.env("LC_ALL", "C").args(["-n", "-c", "3"]);
    if binary != "ping6" {
        cmd.args([
            "-W",
            if cfg!(target_os = "macos") {
                "1000"
            } else {
                "1"
            },
        ]);
    }
    cmd.arg(target).stdout(Stdio::piped()).stderr(Stdio::null());
    execute(&mut cmd, Duration::from_secs(8))
}
fn execute(cmd: &mut Command, timeout: Duration) -> Probe {
    let Ok(mut child) = cmd.spawn() else {
        return Probe::unavailable("execution_failed");
    };
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if start.elapsed() < timeout => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Probe::unavailable("timeout_or_wait_failed");
            }
        }
    }
    match child.wait_with_output() {
        Ok(o) => parse(o.status.code(), &String::from_utf8_lossy(&o.stdout)),
        Err(_) => Probe::unavailable("execution_failed"),
    }
}
fn parse(code: Option<i32>, output: &str) -> Probe {
    // Linux 1 and BSD 2 can mean no replies. A valid summary is mandatory.
    if !matches!(code, Some(0..=2)) {
        return Probe::unavailable("execution_failed");
    }
    let loss = output
        .lines()
        .filter(|l| l.contains("packet loss"))
        .find_map(|line| {
            let before = line.split('%').next()?;
            before.split_whitespace().last()?.parse::<f64>().ok()
        })
        .filter(|n| n.is_finite() && (0.0..=100.0).contains(n));
    let Some(loss) = loss else {
        return Probe::unavailable(if code == Some(0) {
            "no_valid_summary"
        } else {
            "execution_failed"
        });
    };
    let rtt = output
        .lines()
        .filter(|l| l.contains("min/avg/max"))
        .find_map(|line| {
            line.split('=')
                .nth(1)?
                .split('/')
                .nth(1)?
                .trim()
                .parse::<f64>()
                .ok()
        })
        .filter(|n| n.is_finite() && *n >= 0.0);
    if loss < 100.0 && rtt.is_none() {
        return Probe::unavailable("no_valid_rtt");
    }
    Probe {
        rtt,
        loss: Some(loss),
        status: "observed",
        reason: "icmp_summary",
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn network_loss_and_collector_failure_are_distinct() {
        let lost = parse(
            Some(1),
            "3 packets transmitted, 0 received, 100% packet loss",
        );
        assert_eq!(lost.loss, Some(100.0));
        assert_eq!(lost.status, "observed");
        for text in [
            "",
            "ping: Operation not permitted",
            "0% packet loss",
            "NaN% packet loss",
        ] {
            let failure = parse(Some(2), text);
            assert_eq!(failure.loss, None);
            assert_eq!(failure.status, "unavailable");
        }
        assert_eq!(run(None).status, "not_configured");
        assert_eq!(run(Some("-f")).reason, "invalid_target");
    }
    #[test]
    fn parses_linux_and_bsd_success_and_zero() {
        for prefix in ["rtt", "round-trip"] {
            let p = parse(Some(0), &format!("3 packets transmitted, 3 received, 0% packet loss\n{prefix} min/avg/max/stddev = 0/0/0/0 ms"));
            assert_eq!(p.loss, Some(0.0));
            assert_eq!(p.rtt, Some(0.0));
        }
    }
    #[test]
    fn missing_command_and_timeout_have_no_loss_value() {
        assert_eq!(
            execute(
                &mut Command::new("/netwatch-fixture-missing"),
                Duration::from_millis(10)
            )
            .loss,
            None
        );
        let mut cmd = Command::new("sleep");
        cmd.arg("2");
        let before = Instant::now();
        let p = execute(&mut cmd, Duration::from_millis(30));
        assert_eq!(p.reason, "timeout_or_wait_failed");
        assert!(before.elapsed() < Duration::from_secs(1));
    }
    #[test]
    #[ignore = "requires installed ping and loopback ICMP permissions"]
    fn live_loopback_is_observed() {
        let p = run(Some("127.0.0.1"));
        assert_eq!(p.status, "observed");
        assert_eq!(p.loss, Some(0.0));
        assert!(p.rtt.is_some());
    }
}
