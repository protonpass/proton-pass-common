import {library_version, random_words, generate_passphrase, detect_credit_card_type} from "../pkg/proton_pass_web.mjs";

console.log(library_version());

const words = random_words(3);
const passphrase = generate_passphrase(words, {
    separator: "Hyphens",
    capitalise: true,
    include_numbers: true,
    count: 3
});

console.log(passphrase);

const cardType = detect_credit_card_type("4000056655665556");
console.log(cardType);