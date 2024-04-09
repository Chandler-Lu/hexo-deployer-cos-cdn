"use strict";

const https = require("https");
const crypto = require("crypto");

var _ = require('lodash');
var utilityLib = require("utility");
var commonUtils = require("./utils");

const host = "cdn.tencentcloudapi.com";
const service = "cdn";
const action = "PurgeUrlsCache";
const version = "2018-06-06";
const timestamp = parseInt(String(new Date().getTime() / 1000));
const date = getDate(timestamp);

var QcloudSDK = function () {
  this.secretKey = "";
  this.secretId = "";
};

QcloudSDK.prototype.config = function (userConfig) {
  checkUserConfig(userConfig);

  this.secretKey = userConfig.secretKey;
  this.secretId = userConfig.secretId;
};

QcloudSDK.prototype.request = function (actionName, params, callback) {
  checkUserConfig({
    secretKey: this.secretKey,
    secretId: this.secretId,
  });

  // ************* 步骤 1：拼接规范请求串 *************
  const signedHeaders = "content-type;host";
  const hashedRequestPayload = getHash(JSON.stringify(params));
  const httpRequestMethod = "POST";
  const canonicalUri = "/";
  const canonicalQueryString = "";
  const canonicalHeaders = "content-type:application/json; charset=utf-8\n" + "host:" + host + "\n";

  const canonicalRequest =
    httpRequestMethod +
    "\n" +
    canonicalUri +
    "\n" +
    canonicalQueryString +
    "\n" +
    canonicalHeaders +
    "\n" +
    signedHeaders +
    "\n" +
    hashedRequestPayload;

  // ************* 步骤 2：拼接待签名字符串 *************
  const algorithm = "TC3-HMAC-SHA256";
  const hashedCanonicalRequest = getHash(canonicalRequest);
  const credentialScope = date + "/" + service + "/" + "tc3_request";
  const stringToSign = algorithm + "\n" + timestamp + "\n" + credentialScope + "\n" + hashedCanonicalRequest;

  // ************* 步骤 3：计算签名 *************
  const kDate = sha256(date, "TC3" + this.secretKey);
  const kService = sha256(service, kDate);
  const kSigning = sha256("tc3_request", kService);
  const signature = sha256(stringToSign, kSigning, "hex");

  // ************* 步骤 4：拼接 Authorization *************
  const authorization =
    algorithm +
    " " +
    "Credential=" +
    this.secretId +
    "/" +
    credentialScope +
    ", " +
    "SignedHeaders=" +
    signedHeaders +
    ", " +
    "Signature=" +
    signature;

  // ************* 步骤 5：构造并发起请求 *************
  const headers = {
    Authorization: authorization,
    "Content-Type": "application/json; charset=utf-8",
    Host: host,
    "X-TC-Action": action,
    "X-TC-Timestamp": timestamp,
    "X-TC-Version": version,
  };

  const options = {
    hostname: host,
    method: httpRequestMethod,
    headers,
  };

  const req = https.request(options, (res) => {
    let data = "";
    res.on("data", (chunk) => {
      data += chunk;
    });

    res.on("end", () => {});
  });

  req.on("error", (error) => {
    console.error(error);
  });

  req.write(JSON.stringify(params));

  req.end();
};

function checkUserConfig(userConfig) {
  if (!_.isPlainObject(userConfig) || !_.isString(userConfig["secretKey"]) || !_.isString(userConfig["secretId"])) {
    throw new Error(
      "::config function should be called required an object param which contains secretKey[String] and secretId[String]"
    );
  }
}

function sha256(message, secret = "", encoding) {
  const hmac = crypto.createHmac("sha256", secret);
  return hmac.update(message).digest(encoding);
}

function getHash(message, encoding = "hex") {
  const hash = crypto.createHash("sha256");
  return hash.update(message).digest(encoding);
}

function getDate(timestamp) {
  const date = new Date(timestamp * 1000);
  const year = date.getUTCFullYear();
  const month = ("0" + (date.getUTCMonth() + 1)).slice(-2);
  const day = ("0" + date.getUTCDate()).slice(-2);
  return `${year}-${month}-${day}`;
}

var qcloudSDK = new QcloudSDK();

module.exports = qcloudSDK;
