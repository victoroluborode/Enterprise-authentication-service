const setupApp = require("./app.js");

const startServer = async () => {
  try {
    // Setup app with async middleware initialization
    const app = await setupApp();

    const PORT = process.env.PORT || 10000;

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
};

startServer();
