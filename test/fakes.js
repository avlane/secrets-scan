// Fake credentials for tests. They are assembled from pieces so that scanning this
// repository does not find them, and none of them is valid anywhere.
export const AWS_KEY = "AKIA" + "QYLPMN5HHHFPZAM2";
export const GITHUB_TOKEN = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz";
export const SLACK_TOKEN = "xoxb-" + "123456789012-1234567890123-abcdefghijklmnopqrstuvwx";
export const SLACK_WEBHOOK = "https://hooks.slack" + ".com/services/T00000000/B00000000/" + "abcdefghijklmnopqrstuvwx";
export const STRIPE_KEY = "sk_live_" + "0123456789abcdefghijklmn";
export const STRIPE_WEBHOOK = "whsec_" + "0123456789abcdefghijklmnopqrstuv";
export const GOOGLE_API_KEY = "AIza" + "Sy" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456";
export const NPM_TOKEN = "npm_" + "0123456789abcdefghijklmnopqrstuvwxyz";
export const SENDGRID_KEY = "SG." + "abcdefghijklmnopqrstuv" + "." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopq";
export const TWILIO_KEY = "SK" + "0123456789abcdef0123456789abcdef";
export const MAILGUN_KEY = "key-" + "0123456789abcdef0123456789abcdef";
const ALNUM = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
export const PYPI_TOKEN = "pypi-AgEIcHlwaS5vcmc" + ALNUM + "_-";
export const SHOPIFY_TOKEN = "shpat_" + "0123456789abcdef0123456789abcdef";
export const DIGITALOCEAN_TOKEN = "dop_v1_" + "0123456789abcdef".repeat(4);
export const DATABRICKS_TOKEN = "dapi" + "0123456789abcdef0123456789abcdef";
export const SENTRY_TOKEN = "sntrys_" + "eyJpYXQiOjE2OTk5OTk5OTksInVybCI6Imh0dHBzOi8vc2VudHJ5";
export const SQUARE_TOKEN = "sq0atp-" + "0123456789abcdefghijkl";
export const DISCORD_WEBHOOK = "https://discord" + ".com/api/webhooks/" + "123456789012345678/" + ALNUM + "_-abcdefgh";
export const AZURE_STORAGE_KEY = "AccountKey=" + ALNUM + "0123456789abcdefghijklmn" + "==";
export const PRIVATE_KEY_HEADER = "-----BEGIN RSA " + "PRIVATE KEY-----";
