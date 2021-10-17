#include <secp256k1_ecdh.h>
#include <stdio.h>
#include <curl/curl.h>
#include <string>
#include <cstring>
#include <json-c/json.h>
#include <iostream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <memory>
#include "segwit_addr.h"
#define REGTEST 1
/* We need a port for our RPC **/
#if REGTEST
  #define HRP "bcrt"
  #define PORT 18443
#elif TESTNET
  #define HRP "tb"
  #define PORT 18332
#elif SIGNET
  #define HRP "tb"
  #define PORT 38332
#else 
  #define HRP "bc"
  #define PORT 8332
#endif

/** A bit of laziness */
#define GET(json, item) json_object_object_get(json, item)
#define CMP(obj1, obj2) json_object_equal(obj1, obj2)
#define GET_LENGTH(json) json_object_array_length(json)
#define GET_I(json, i) json_object_array_get_idx(json, i)

/* Remove double quotes and add to a vector */
#define STRIP_ADD(vec, json, size)  vec.push_back (json_object_to_json_string_ext(json, 0));\
                              memcpy(vec.back().data(), vec.back().data() + 1, size);\
                              vec.back().resize(size);
/** Yes, Global variables! What a shame...*/
char url[1000] = {0};
const auto v0_witness = json_object_new_string("witness_v0_keyhash"); // Alloc this only once

/** Read the cookie for calling the RPC */
static void getCookie(int testNet, char* cookie_str)
{
  FILE *cookie;
  if(testNet)
    cookie = fopen("/home/erik/.bitcoin/regtest/.cookie", "r");
  else
    cookie = fopen("/home/erik/.bitcoin/.cookie", "r");
  if(cookie == NULL)
  {
    puts("getCookie(): FATAL ERROR loading the cookie file\n");
    exit(1);
  }
  fread(cookie_str, sizeof(char), 75, cookie);
  fclose(cookie);
  cookie_str[75] = '\0';
}
/** Callback used for curl */
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}
/** Call the RPC and write back the result */
static void callRPC(std::string& readBuffer, const char *data) {
  CURL *curl;
  CURLcode res;
  struct curl_slist *headers = NULL;
  headers = curl_slist_append(headers, "Content-Type: application/json");
  curl = curl_easy_init();
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, true);  // Uncomment this for throbleshooting RPC
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
  }
} 
/** Get the transactions of a block
 * Note to myself: Take extra care with theese roots, never loose the reference and ALWAYS free it
 * by using the json_object_put. If not used carefully, may cause serious problems
 */
int getBlock(std::vector <std::string>& tx_list, int blk) {
  std::string readBuffer;
  char cmd [200];
  
  sprintf(cmd, "{\"jsonrpc\":\"1.0\",\"id\":\"curltext\",\"method\":\"getblockhash\",\"params\":[%d]}", blk);
  callRPC(readBuffer, cmd);

  json_object *root = json_tokener_parse(readBuffer.c_str());
  json_object *res = json_object_object_get(root, "result");

  sprintf(cmd, "{\"jsonrpc\":\"1.0\",\"id\":\"curltext\",\"method\":\"getblock\",\"params\":[%s]}", json_object_to_json_string_ext(res, 0));
  /** Cleanup a feel things */
  readBuffer.clear();
  json_object_put(root);
  callRPC(readBuffer, cmd);

  root = json_tokener_parse(readBuffer.c_str());
  res = json_object_object_get(root, "result");
  const auto tx_list_root = json_object_object_get (res, "tx");

  if (!tx_list_root) {
    json_object_put(root);
    return 0;
  }
  int txIn = json_object_array_length(tx_list_root);

  /** Coinbase only, nothing to do... */
  if(txIn == 1) {
    json_object_put(root);
    return 0;
  }
  tx_list.resize (txIn - 1);
  /** Don't use coinbase */
  for (unsigned int i = 1; i < txIn; i++) {
    tx_list[i - 1] = json_object_to_json_string_ext(json_object_array_get_idx(tx_list_root, i), 0);    
  }
  json_object_put(root);

  return 1;
}
/** This is used for converting ascii hexademal string to bytes */
static const unsigned char mask[] = {
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                                0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                                0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A, 0x0B, 0x0C,
                                0x0D, 0x0E, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            }; 
/** Convert a hex-string in bytes */          
const void str2bytes(unsigned char *out, std::string str) {
    if(out == nullptr){
        printf("out must not be null");
        return ;
    }
    for(unsigned int i = 0; i < str.length()/2; i ++) {
        out[i] = (mask[str[(2*i)]] << 4) | (mask[str[((2*i)) + 1]]);
    }
}
const void str2bytes(unsigned char *out, char *str, size_t strlen) {
    if(out == nullptr){
        printf("out must not be null");
        return ;
    }
    for(unsigned int i = 0; i < strlen/2; i ++) {
        out[i] = (mask[str[(2*i)]] << 4) | (mask[str[((2*i)) + 1]]);
    }
}        
/** Compute the sha256 of some data */
void sha256 (char unsigned out[32], const unsigned char *data, size_t len) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_sha256();
  unsigned int md_len;
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, data, len);
  EVP_DigestFinal_ex(mdctx, out, &md_len);
  EVP_MD_CTX_free(mdctx);
}
/** Compute the RIPMD-160 of some data */
void ripmd160 (char unsigned out[20], const unsigned char *data, size_t len) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_ripemd160();
  unsigned int md_len;
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, data, len);
  EVP_DigestFinal_ex(mdctx, out, &md_len);
  EVP_MD_CTX_free(mdctx);
}
/** Compute the sha256 of some data */
void sha512(unsigned char out[64], unsigned char data[32], unsigned int len) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  const EVP_MD *md = EVP_sha512();
  unsigned int md_len;
  EVP_DigestInit_ex(mdctx, md, NULL);
  EVP_DigestUpdate(mdctx, data, len);
  EVP_DigestFinal_ex(mdctx, out, &md_len);
  EVP_MD_CTX_free(mdctx);
}
/** Should behave like the OP_HASH160 from bitcoin script, with is the ripmd160(sha256(x)) */
void hash160 (unsigned char out[20], const unsigned char *data, size_t len) {
  unsigned char sha256_out[32];
  sha256 (sha256_out, data, len);
  ripmd160 (out, sha256_out, 32);
}
/** Is the output mine? We need the pk of the sender and our pair (a, B). Here we take the ECDH and see if the hash matches the passed `commitment`
 * @param ctx: A SECP256K1 context
 * @param priv_view_key: The DH private key
 * @param recveer_pubkey: The public part of the spend key (i.e B)
 * @param pk: The sender pk
 * @param commitment: The output spk, if we get a equal result, the output is mine
*/
int isForMe
  (
    secp256k1_context *ctx,
    unsigned char dh_out[32],
    const unsigned char priv_view_key[32],
    const secp256k1_pubkey recveer_pubkey,
    const secp256k1_pubkey pk,
    const std::string& commitment
  ) {
  /** We have P, a and B
  * The commitment is H(Pa)G + B
  */
  /** dh_out = Pa (ECDH)*/
  if (!ctx || !priv_view_key) return 0;

  //unsigned char dh_out[32];
  int ret = secp256k1_ecdh(ctx, dh_out, &pk, priv_view_key, secp256k1_ecdh_hash_function_default, NULL);
  secp256k1_pubkey S, P;

  /** S = dh_out*G */
  ret = secp256k1_ec_pubkey_create(ctx, &S, dh_out);
  
  secp256k1_pubkey const *keys [] = { &S, &recveer_pubkey };
  /** P = S + recveer_pubkey */
  ret = secp256k1_ec_pubkey_combine(ctx, &P, keys, 2);
  
  /** If P == commitment, is for me! */
  unsigned char ser_pk[33], hash160_ser_data[20];
  size_t output_len = 33;
  
  secp256k1_ec_pubkey_serialize(ctx, ser_pk, &output_len, &P, SECP256K1_EC_COMPRESSED);
  hash160 (hash160_ser_data, ser_pk, 33);

  unsigned char com[20];
  str2bytes(com, commitment);
  if (memcmp(hash160_ser_data, com + 1, 20) == 0)
    return 1;
  return 0;
}

/** In this context, the invoice is a one-time address generated from the stealth-address 
 * @param ctx: A libsecp256k1 context
 * @param out: The resulting pubkey
 * @param priv_key: The view private key
 * @param a: The inner pubkey, used only for ECDH
 * @param b: The outer pk, will be twicked for creating the final pk 
*/
int createInvoice
  (
    secp256k1_context *ctx,
    secp256k1_pubkey *out,
    const unsigned char priv_key[32],
    secp256k1_pubkey& a,
    secp256k1_pubkey& B
  ) {

    unsigned char dh_out[32];
    if (!secp256k1_ecdh(ctx, dh_out, &a, priv_key, secp256k1_ecdh_hash_function_default, NULL))
      return 0;
    
    secp256k1_pubkey S, P;

    if (!secp256k1_ec_pubkey_create(ctx, &S, dh_out))
      return 0;
  
    secp256k1_pubkey const *keys [] = { &S, &B };
    /** P = S + recveer_pubkey */
    if (!secp256k1_ec_pubkey_combine(ctx, out, keys, 2))
      return 0;
    
    return 1;
  }

/** Sweep the transaction with `txId` and get the pubkeys and the spk hashes
 * @param pks: A vector of strings, will return all public keys from the inputs
 * @param commitments: These are the hashes found inside the scriptPubKey, e.g. in v0-witness p2wpkh is the hash160 of the pk 
 * @param txid: A string containing the id of a given transaction.
*/
int getTransaction(std::vector <std::string>& pks, std::vector <std::string>& commitments, std::string txId) {

  std::string readBuffer;
  /* Call the RPC to get the transaction data */
  char cmd[200];
  sprintf(cmd, "{\"jsonrpc\":\"1.0\",\"id\":\"curltext\",\"method\":\"getrawtransaction\",\"params\":[%s, true]}", txId.c_str());
  callRPC(readBuffer, cmd);
  const auto root = json_tokener_parse (readBuffer.c_str());
  /* Take the userfull data from the transaction */
  auto vins  = json_object_object_get(json_object_object_get(root,"result"), "vin");
  auto vouts = json_object_object_get(json_object_object_get(root, "result"),"vout");
  if (!vins || !vouts) {
    json_object_put(root);
    return 0;
  };

  /* How many inputs and outputs we've got? */
  int nVin  = json_object_array_length(vins); 
  int nVout = json_object_array_length(vouts);
  
  json_object *vin, *vout;
  /* Loop throught the inputs, we need the pubKeys */
  for (unsigned int i = 0; i < nVin; i++) {
    vin = json_object_array_get_idx(vins, i);

    /* It's a witness transaction? */
    const auto txWitness = GET(vin, "txinwitness");
    if (txWitness) {
      if(GET_LENGTH(txWitness) == 2) {
        //This must be the case of a p2wpkh, let's take the pk out!
        STRIP_ADD(pks, GET_I(txWitness, 1), 66);
      }
      // Maybe it's p2tr or p2wsh... @TODO
      continue;
    }
    /** @TODO: Legacy p2pk, p2pkh and p2sh */
  }
  /* Now the outputs, does it belongs to me? */
  for (unsigned int i = 0; i < nVout; i++) {
    vout = GET_I(vouts, i);
    /** Is it v0-p2wpkh? */
    if (CMP (GET (GET (vout, "scriptPubKey"), "type"), v0_witness) ) {
      STRIP_ADD (commitments, GET (GET (vout, "scriptPubKey"), "asm"), 42);
    }
    /** @TODO: Take othets outputs aswell */
  }
  json_object_put(root);

  return 0;
}

/** The height of the best chain */
int getChainSize () {
  const char cmd[] = "{\"jsonrpc\":\"1.0\",\"id\":\"curltext\",\"method\":\"getblockchaininfo\",\"params\":[]}";
  std::string readBuffer;
  callRPC(readBuffer, cmd);

  if (readBuffer.size() == 0) {
    puts("getChainSize(): FATAL ERROR calling the RPC\n");
    exit(1);
  }
  json_object *root = json_tokener_parse(readBuffer.c_str());
  if (!root) {
    puts ("getChainSize(): FATAL ERROR invalid response from rpc");
    exit(1);
  }
  try
  { 
    const auto res = json_object_get_int(GET(GET(root, "result"), "blocks"));
    return res;
  }
  catch(const std::exception& e)
  {
    std::cerr << e.what() << '\n';
  }
  return 0;
}

int verifyTransaction(
                        secp256k1_context *ctx,
                        unsigned char dh_out[32],
                        std::vector <std::string> pks,
                        std::vector <std::string> commitmens,
                        secp256k1_pubkey& B,
                        const unsigned char a[32]
                      ) {
  secp256k1_pubkey sender_pubkey;
  unsigned char pub_bytes[33];

  for (auto pk : pks) {
    for (auto com : commitmens) {
      str2bytes(pub_bytes, pk.c_str());
        if (!secp256k1_ec_pubkey_parse(ctx, &sender_pubkey, pub_bytes, 33 )) {
          printf("Error!\n");
          exit(1);
      }
      if (isForMe (ctx,dh_out, a, B, sender_pubkey, com) == 1) {
        return 1;
      }
    }
  }
  return 0;
}
/** Iterates throught the chain, looking for incoming transactions */
int scan(secp256k1_pubkey& B, const unsigned char a[32], char *rpc) {
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  FILE *wallet_txs = fopen("wallet.db", "wb");
  char cookie[100];

  /** @todo: Password*/
  if (strlen(rpc) == 0) {
    puts("LOG: No RPC string informed, trying read the cookie");
    getCookie(1, cookie);
    sprintf(url, "http://%s@127.0.0.1:%d", cookie, PORT);
  } else {
    strcpy(url, rpc);
  }
  const unsigned int tip = getChainSize();
  printf ("LOG: Scanning from 0 to %d\n", tip);
  unsigned char dh_out[32];
  std::vector <std::string> pks, tx_list, commitmens;

  for (unsigned int block = 0; block <= tip; block++) {
    if (block % 1000 == 0)
      printf("Analysing block: %i\n", block);
    tx_list.clear();
    /* Coinbase tx don't have input's pubkeys, so our system doesn't works */
    if(getBlock(tx_list, block) == 0) {
      continue;
    }
    /* With stealth addresses, we need loop through each tx, hoping it's for us */
    for (auto i : tx_list) {
      pks.clear(); commitmens.clear();
      getTransaction(pks, commitmens, i);
      if (verifyTransaction(ctx, dh_out, pks, commitmens, B, a)) {
        printf("New wallet tx %s\n", i.c_str());
        fwrite(i.data() + 1, 1, 64 , wallet_txs); // This +1 strips off the double quotes
        fwrite(dh_out, 1, 32, wallet_txs);
      }
    }
  }
  fclose(wallet_txs);
  secp256k1_context_destroy(ctx);
  return 0;
}
/** Get a p2wpkh address from a stealth address */
int getAddress(secp256k1_pubkey& A, secp256k1_pubkey& B, const unsigned char *r) {
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);  
  secp256k1_pubkey invoice, sender_pubkey;

  /*hash(senderPrivKey * A)*G + B*/
  if (!createInvoice(ctx, &invoice, r, A, B))
    return 1;
  /** Serialize then... */
  unsigned char ser_invoice[33];
  size_t ser_size = 33;
  secp256k1_ec_pubkey_serialize(ctx, ser_invoice, &ser_size, &invoice, SECP256K1_EC_COMPRESSED);
  unsigned char hash[20];
  char address[73 + strlen(HRP)]; // This is allowed since HRP is know at compile time
  /**... get the witness v0 address... */
  hash160(hash, ser_invoice, 33);
  segwit_addr_encode (address, HRP, 0, hash, 20);

  /** ...and show! */
  printf ("%s\n", address);

  secp256k1_context_destroy(ctx);
  return 0;
}
int getAddress(const unsigned char A[33], const unsigned char B[33], const unsigned char r[32]) {
  secp256k1_pubkey parsedA, parsedB;
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

  if (!secp256k1_ec_pubkey_parse(ctx, &parsedA, A, 33 ))
    return 1;
  if (!secp256k1_ec_pubkey_parse(ctx, &parsedB, B, 33 ))
    return 1;
  return getAddress (parsedA, parsedB, r);
}

/** Used internally*/
struct args_t {
  char stealthAddress[132] = {0}; // A stealth address is two pubkeys A and B
  char privKey[64] = {0};
  char seed[100] = {0};
  char rpc[1000] = {0};
  char tx_id[64] = {0};
};
/** Possible commands, just only at once */
enum class CMD {UNDEFINED, GET_INVOICE, REESCAN, LIST_ADDRESS, LIST_TRANSACTIONS, CREATE_WALLET, PRIVATE_KEY};
/** Show a cli help of all our commands */
void showUsage() {
  puts("Usage: stealth-out command [optins]");
  puts(" invoice: Create a new invoice");
  puts("   -a <stealth address>        The recever's stealth address");
  puts("   -p <sender Private Key      The sender's private key. Must be the same from the UTXO being spent");
  puts(" create-wallet:                Create a new wallet");
  puts("   -s <seed>                   The wallet's seed");
  puts(" show-address                  Print the stealth address for a given wallet");
  puts(" list-transactions             List all transactions to one wallet");
  puts(" rescan                        Rescan the blockchain looking for wallet's txs");
  puts("   -c <rpc_connection>         The params used for comunicating with Bitcoin Core");
}
/** Parse the args from the command line */
CMD parseArgs(int argc, char **argv, struct args_t& args) {
  
  CMD cmd = CMD::UNDEFINED;
  
  if (!strcmp (argv[1], "invoice")) 
    cmd = CMD::GET_INVOICE;
  else if (!strcmp (argv[1], "create-wallet"))
    cmd = CMD::CREATE_WALLET;
  else if (!strcmp (argv[1], "show-address"))
    cmd = CMD::LIST_ADDRESS;
  else if (!strcmp (argv[1], "list-transactions"))
    cmd = CMD::LIST_TRANSACTIONS;
  else if (!strcmp (argv[1], "rescan"))
    cmd = CMD::REESCAN;
  else if (!strcmp (argv[1], "spend"))
    cmd = CMD::PRIVATE_KEY;
  else {
    printf("ERROR: Unknow command %s\n\n", argv[1]);

    showUsage();
    return CMD::UNDEFINED;
  }
  for (unsigned int i = 2; i < argc; i++) {
      switch (argv[i][1])
      {
        case 'r': {
          if (argc - i - 1 == 0 || strlen(argv[++i]) < 1) {
            puts("ERROR: Insuficiente params, missing a rpc address\n\n");

            showUsage();
            return CMD::UNDEFINED;
          }
          if (strlen(argv[i]) > 100) {
            puts ("ERROR: RPC string too big");
            return CMD::UNDEFINED;
          }
          memcpy(args.rpc, argv[i], strlen(argv[i]));
          break;
        }
        case 't': {
          if (argc - i - 1 == 0 || strlen(argv[++i]) < 1) {
            puts("ERROR: Insuficiente params, missing a  tx\n\n");

            showUsage();
            return CMD::UNDEFINED;
          }
          if (strlen(argv[i]) < 64) {
            puts ("ERROR: tx id too short");
            return CMD::UNDEFINED;
          }
          memcpy(args.tx_id, argv[i], 64);
          break;
        }
        case 'a':
          if (argc - i - 1 == 0) {
            puts("ERROR: Insuficiente params, missing a stealth address\n\n");

            showUsage();
            return CMD::UNDEFINED;
          }
          if (strlen(argv[++i]) != 132) {
            printf("ERROR: Stealth address %s is too short expected 132, found %d!\n\n", argv[i], strlen(argv[i]));

            showUsage();
            return CMD::UNDEFINED;
          }
          memcpy(args.stealthAddress, argv[i], 132);
          break;
      case 'p':
        if (argc - i - 1 == 0) {
          puts("ERROR: Insuficiente params, missing a private key\n\n");

          showUsage();
          return CMD::UNDEFINED;
        }
        if (strlen(argv[++i]) != 64) {
          printf ("ERROR: Private key %s is too short %d\n", argv[i], strlen(argv[i]));
        
          showUsage();
          return CMD::UNDEFINED;
        }
        memcpy(args.privKey, argv[i], 64);

        break;
    case 's':
      if (argc - i - 1 == 0) {
        puts("ERROR: Insuficiente params, missing a mnemonic\n\n");

        showUsage();
          return CMD::UNDEFINED;
        }
        memcpy(args.seed, argv[i], strlen(argv[++i]));

        break;
    default:
      printf("Unknow param -%c\n\n", argv[i][1]);
      showUsage();
      break;
    }
    
  }

  return cmd;
}
/** Load a wallet from disk */
FILE* loadWallet() {
  return fopen("wallet.dat", "rb");
}
/** Derive a child key from a parent one. It's the hardened derivation from BIP32 but the index */
void derive(unsigned char key_out[32], unsigned char chaincode_out[32], unsigned char input[32], unsigned char chaincode_in[32]) {
  unsigned char out[64];
  unsigned int md_out;
  auto res = HMAC(EVP_sha512(), input, 32, chaincode_in, 32, out, &md_out);
  memcpy(key_out, out, 32);
  memcpy(chaincode_out, out + 32, 32);
}
/** Display the address for a given wallet */
int showWalletAddress(FILE *wallet) {
  unsigned char seed[32], hash[64];
  fread(seed, 1, 32, wallet);
  sha512(hash, seed, 32);
   
  unsigned char key_out_a[32], chaincode_a[32], key_out_b[32], chaincode_b[32];
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  secp256k1_pubkey pkA, pkB;
  /** a */
  derive(key_out_a, chaincode_a, hash, hash + 32);

  if (!secp256k1_ec_pubkey_create(ctx, &pkA, key_out_a))
    return 1;
  /** b */
  derive(key_out_b, chaincode_b, key_out_a, chaincode_a);

  if (!secp256k1_ec_pubkey_create(ctx, &pkB, key_out_b))
    return 1;
  unsigned char serA[33], serB[33];

  size_t out_len = 33;
  if (   !secp256k1_ec_pubkey_serialize(ctx, serA, &out_len, &pkA, SECP256K1_EC_COMPRESSED)
      || !secp256k1_ec_pubkey_serialize(ctx, serB, &out_len, &pkB, SECP256K1_EC_COMPRESSED))
        return 1;
  for (unsigned int i = 0; i < 33; i++)
    printf ("%02x", serA[i]);
  for (unsigned int i = 0; i < 33; i++)
    printf ("%02x", serB[i]);
  secp256k1_context_destroy(ctx);
  return 0;
}
/** */
int getWalletInternalKey (secp256k1_pubkey& pkB, unsigned char a[32], FILE *wallet) {
  unsigned char seed[32], hash[64];
  fread(seed, 1, 32, wallet);
  sha512(hash, seed, 32);
   
  unsigned char chaincode_a[32], key_out_b[32], chaincode_b[32];
  secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  /** a */
  derive(a, chaincode_a, hash, hash + 32);

  /** b */
  derive(key_out_b, chaincode_b, a, chaincode_a);

  if (!secp256k1_ec_pubkey_create(ctx, &pkB, key_out_b))
    return 1;
  secp256k1_context_destroy(ctx);
  return 0;
}
int main(int argc, char **argv) {
  if (argc < 2) {
    showUsage();
    return 1;
  }
  struct args_t parsedArgs;
  CMD command = parseArgs(argc, argv, parsedArgs);
  
  switch (command)
  {
  case CMD::UNDEFINED: {
   return 1; 
  break;
  }
  case CMD::CREATE_WALLET: {
    if (strlen((char *)parsedArgs.seed) == 0) {
      puts("A seed is required for creating a wallet");
      return 1;
    }
    unsigned char seed[32];
    sha256(seed, (unsigned char *)parsedArgs.seed, strlen((char *)parsedArgs.seed));
    FILE *wallet = fopen("wallet.dat", "wb");
    fwrite(seed,  sizeof(char), 32, wallet );
    puts ("Wallet created!");
    
    break;
  }
  case CMD::LIST_ADDRESS: {
      auto wallet = loadWallet();
      if (!wallet) {
        puts("No wallet found, use create-wallet to create a new one");
        return 1;
      }
      showWalletAddress(wallet);
    }
  case CMD::GET_INVOICE: {
    if (strlen((char *)parsedArgs.stealthAddress) == 0) {
      puts("No stealth address specified");
      return 1;
    }

    if (strlen((char *)parsedArgs.privKey) == 0) {
      puts("No privite key specified");
      return 1;
    }
    unsigned char A[33], B[33], r[32];
    str2bytes(A, parsedArgs.stealthAddress, 66);
    str2bytes(B, parsedArgs.stealthAddress + 66, 66);
    str2bytes(r, parsedArgs.privKey, 64);

    if (getAddress(A, B, r) != 0) {
      puts("A fatal erro happened");
      return 1;
    }
    break;
  }
  case CMD::REESCAN: {
    auto wallet = loadWallet();
    if (!wallet) {
      puts("No wallet found, use create-wallet to create a new one");
      return 1;
    }
    secp256k1_pubkey B;
    unsigned char a[32];
    if (getWalletInternalKey(B, a, wallet) != 0) {
      puts ("An unknow error happened");
      return 1;
    }
    puts ("WARNING: Rescan may take a while to proccess");

    scan(B, a, parsedArgs.rpc);
    break;
  }

  case CMD::LIST_TRANSACTIONS: {
    FILE *wallet_transactions = fopen("wallet.db", "rb");
    if (!wallet_transactions) { 
      puts("ERROR: Reading wallet.dat");
      return 1;
    }
    
    while (!feof(wallet_transactions)) {
      unsigned char tx_id[64] = {0}, tx_dh[32] = {0};
      if (fread(tx_id, 1, 64, wallet_transactions) > 0)  {
        fread(tx_dh, 1, 32, wallet_transactions);
        printf ("| -> ");
        for (unsigned int i = 0; i < 64; i++)
          printf("%c", tx_id[i]);
        puts("");
      }
    }
    
    break;
  }
  case CMD::PRIVATE_KEY: {
    FILE *wallet_transactions = fopen("wallet.db", "rb");
    FILE *wallet = fopen("wallet.dat", "rb");

    if (!wallet_transactions || !wallet) { 
      puts("ERROR: Reading wallet.dat");
      return 1;
    }
    if (strlen((char *)parsedArgs.tx_id) == 0) {
      puts("ERROR: A txid is required");
      return 1;
    }
    
    while (!feof(wallet_transactions)) {
      unsigned char tx_id[64] = {0}, tx_dh[32] = {0};
      if (fread(tx_id, 1, 64, wallet_transactions) > 0)  {
        if (memcmp(tx_id, parsedArgs.tx_id, 64) == 0) {
            fread(tx_dh, 1, 32, wallet_transactions);
            unsigned char seed[32], hash[64];
            fread(seed, 1, 32, wallet);
            sha512(hash, seed, 32);
   
            unsigned char key_out_a[32], chaincode_a[32], key_out_b[32], chaincode_b[32];
  
            /** a */
            derive(key_out_a, chaincode_a, hash, hash + 32);
            secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

            /** b */
            derive(key_out_b, chaincode_b, key_out_a, chaincode_a);

            if (!secp256k1_ec_privkey_tweak_add(ctx, tx_dh, key_out_b)) return 1;
            for (unsigned int i = 0; i < 32; i++)
              printf("%02x", tx_dh[i]);
            puts("");
        }
      }
    }
  }
  default:
    break;
  }
}
