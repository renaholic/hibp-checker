import { createHash } from 'crypto';
import jsonFile from './bitwarden_export_20240922171324.json';

// only grab necessary structure from the JSON file
interface JSON {
  items: Item[];
}
interface Item {
  folderId: string | null;
  deletedDate: string | null;
  login: {
    password: string;
  };
}

const selfEntries = (jsonFile as JSON).items.filter(
  (x) =>
    x.folderId === null &&
    x.deletedDate === null &&
    !!x.login &&
    !!x.login.password
);

// try to group by first 5 characters of the password hash
// if they so happen to be the same to reduce duplicate requests towards the API
const passwordMap = {} as {
  [hash: string]: {
    suffix: string;
    password: string;
  }[];
};

const throttleMs = 100;

function generatePasswordDigest(password: string) {
  const passwordBuffer = Buffer.from(password);
  const passwordDigest = createHash('sha1').update(passwordBuffer).digest();

  // convert digest to string
  const formattedDigest = Array.from(new Uint8Array(passwordDigest))
    .map((x) => x.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();

  return [formattedDigest.substring(0, 5), formattedDigest.substring(5)];
}

// push password hashes into hash map
selfEntries.forEach((entry) => {
  const password = entry.login.password;
  const [first5Char, suffix] = generatePasswordDigest(password);

  if (!passwordMap[first5Char]) passwordMap[first5Char] = [];

  // if the suffix is already in the list, then we don't need to add it
  if (passwordMap[first5Char].findIndex((e) => e.suffix === suffix) !== -1)
    return;

  passwordMap[first5Char].push({ suffix, password });
});

function wait(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

(async () => {
  for (const [first5Char, suffixes] of Object.entries(passwordMap)) {
    console.log(`Checking ${first5Char}...`);
    // https://haveibeenpwned.com/API/v2#SearchingPwnedPasswordsByRange
    await fetch(`https://api.pwnedpasswords.com/range/${first5Char}`)
      .then((response) => response.text())
      .then((data) => {
        const responseEntries = data.split('\n');
        suffixes.forEach(({ suffix, password }) => {
          const matchingEntry = responseEntries.find((x) =>
            x.startsWith(suffix)
          );
          if (!matchingEntry) return;

          const parts = matchingEntry.split(':');
          const occurrence = parts[1];
          if (parseInt(occurrence) > 5)
            console.log(
              `Password ${password} is compromised with occurrences of ${occurrence}`
            );
        });
      })
      .catch((error) => {
        console.error('Error fetching data:', error);
      });
    await wait(throttleMs);
  }
})();
