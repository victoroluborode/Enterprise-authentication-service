module.exports = {
  apps: [
    {
      name: "event-ingestion-api",
      script: "src/server.js",
      env: {
        NODE_ENV: "development",
        PORT: 3000,
        DATABASE_URL: require("dotenv").config({ path: ".env" }).parsed
          .DATABASE_URL,
      },
      env_production: {
        NODE_ENV: "production",
        PORT: 4000,
        DATABASE_URL: require("dotenv").config({ path: ".env.production" })
          .parsed.DATABASE_URL,
      },
    },
  ],
};
