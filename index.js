import readline from "readline";

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const C = {
  blue: "\x1b[34m",
  green: "\x1b[32m",
  cyan: "\x1b[36m",
  bold: "\x1b[1m",
  reset: "\x1b[0m"
};

let metrics = {
  requests: 0,
  success: 0,
  errors: 0
};

function header() {
  console.clear();
  console.log(C.blue + C.bold + "METRICS ENGINE" + C.reset);
  console.log(C.cyan + "Real-Time Performance Monitor" + C.reset);
  console.log("");
}

function drawBar(label, value) {
  const bar = "█".repeat(value);
  console.log(C.green + label + ": " + bar + " (" + value + ")" + C.reset);
}

function dashboard() {
  header();
  drawBar("Requests", metrics.requests);
  drawBar("Success ", metrics.success);
  drawBar("Errors  ", metrics.errors);
  console.log("");
  console.log(C.blue + "cmd: hit | fail | reset | exit" + C.reset);
  console.log("");
}

function prompt() {
  rl.question(C.blue + "metrics> " + C.reset, handle);
}

function handle(cmd) {
  switch (cmd.trim()) {
    case "hit":
      metrics.requests++;
      metrics.success++;
      dashboard();
      prompt();
      break;

    case "fail":
      metrics.requests++;
      metrics.errors++;
      dashboard();
      prompt();
      break;

    case "reset":
      metrics = { requests: 0, success: 0, errors: 0 };
      dashboard();
      prompt();
      break;

    case "exit":
      console.log(C.green + "\nMetrics Engine Shutdown\n" + C.reset);
      rl.close();
      break;

    default:
      dashboard();
      prompt();
  }
}

dashboard();
prompt();
