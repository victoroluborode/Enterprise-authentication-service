function startTimer(label = "TOTAL") {
  const start = process.hrtime.bigint();
  return {
    log: (step) => {
      const now = process.hrtime.bigint();
      console.log(
        `${step}:`,
        (Number(now - start) / 1_000_000).toFixed(2),
        "ms"
      );
    },
    end: () => {
      const end = process.hrtime.bigint();
      console.log(
        `${label}:`,
        (Number(end - start) / 1_000_000).toFixed(2),
        "ms"
      );
    },
  };
}

module.exports = { startTimer };
