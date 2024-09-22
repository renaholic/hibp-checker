# hibp-checker

You should read the code before running it.

Please feel free to modifiy the code if you do not want the password to be shown in the console.

This repo uses Have I Been Pawned API to check if any of your passwords have been leaked in a data breach.
Featuring minial dependencies of only `crypto` and `typescript`.

To run:

- export your password (in a trusted environment) from bitwardern into the project root (e.g. ./bitwarden_export_20240922171324.json)

```bash
bun run index.ts
```

- make sure you delete the password file after running the script.

This project was created using [Bun](https://bun.sh) v1.1.24.
