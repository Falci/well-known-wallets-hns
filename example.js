const { init, Strategy } = require('./lib');

init('192.168.1.55'); // HSD node

// most secure option
(async () => {
    console.log('CA_AND_DANE', await Strategy.CA_AND_DANE('falci.me'));
})();

// CA based
(async () => {
    console.log('JUST_CA', await Strategy.JUST_CA('falci.me'));

    // Other coins:
    console.log('BTC', await Strategy.JUST_CA('falci.me', 'BTC'));
})();

// DANE first, if fail try CA
(async () => {
    console.log('DANE_OR_CA', await Strategy.DANE_OR_CA('proofofconcept'));
})();

// DANE based
(async () => {
    console.log('JUST_DANE', await Strategy.JUST_DANE('iamfernando'));
})();

// CA first, if fail try DANE
(async () => {
    console.log('CA_OR_DANE', await Strategy.CA_OR_DANE('proofofconcept'));
})();
