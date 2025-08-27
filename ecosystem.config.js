module.exports = {
  apps: [
    {
      name: "event-ingestion-api",
      script: "src/server.js",
      env: {
        NODE_ENV: "development",
        PORT: 3000,
        DATABASE_URL: "postgresql://user:pass@localhost:5432/secureauthdb",
      },
      env_production: {
        NODE_ENV: "production",
        PORT: 4000,
        DATABASE_URL:
          "postgresql://postgres.dlmkpjtlyjgfjlnjezrx:IAMdamilare170@aws-1-eu-central-1.pooler.supabase.com:5432/postgres",
      },
    },
  ],
};
