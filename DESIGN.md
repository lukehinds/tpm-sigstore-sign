We use the EK Pub to encrypt a secret, which has a reference to the AK and only the TPM can unlock that 
challenge as it has the EK Private.

Proving a key is on the same TPM as the EK is complicated because EK can’t simply sign an attestation. Instead, we use a challenge and response protocol called Credential Activation where a certificate authority encrypts a secret then asks the EK to decrypt it.

TPM generates AK

We then hash the AK as a challenge and ask the TPM to unencrypt.



https://cloud.google.com/compute/docs/reference/rest/v1/instances/getShieldedInstanceIdentity
https://cloud.google.com/compute/shielded-vm/docs/retrieving-endorsement-key

```
{
  "kind": "compute#shieldedInstanceIdentity",
  "signingKey": {
    "ekPub": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0VwxlBWLhIdTiJyU23eF\nMSPRiJgEpBtev5txwRMX7OPLy/EXhaXJrjMi6zv+p0xG5/OoX1ge0cB2ul/Ulxvs\nXGMnAfJ2WKBGlOIYFppOSDHeQXSYMIbW9WxH7yXM7yJEGCK1l0Uyxz/UZz9yb/l9\nxgcMjY6Q96ALkaOntRr1a3BSzXEj6LE5MTwKNCZ1iSMYAv2J4CzE3TsSrp1WsRIP\nOm3cLULujTlB/LwHaZU0omC6h5y+923Z2toHdF+xQFQpDmouyLfVj/PQqzXqVow0\nsFcp8Os0t6G+ePPaWNUIwqQf7bIuUdPFs03bqx2j34a4JJqXdcR07cgCmgDA3iwD\n+QIDAQAB\n-----END PUBLIC KEY-----\n"
  },
  "encryptionKey": {
    "ekPub": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9cEG5QF89cZbMOMCWYjq\n/ruq676xjy3b4ClrDdoFB2U1zdF1RBwBAtoIjG0xluEunqypIVYNxWZ1B9T+g+W+\n+CTnuTKwntD8u0ZMHHM2utxmD19xW/LcpLxpg9PthDXWU7bI16zA+qaJpIVxOpqe\nVkTQZWK3x8DZgBXfvKEN2tlngqEIer2kGr3y+9ixg/59DW0bzvsMbuI+k8CxDd8U\nMnBC0wMDrPg/h/Kl17yuIZWYu+VvZhavlNByv8W0V5ViA9D176JPS8tPikJro5rx\nwxeCD8AaCRvYCLJ+JOpXRvhbgdmqOQh7DGn2wEsc8XXGkhx3Z2QeKwEpgFTlEUFp\n0QIDAQAB\n-----END PUBLIC KEY-----\n"
  }
}
```

1. Create EK (From seed, so deterministic)
2. Create AK along with AK Pub
3. Create a CSR (server side), but with a token stuffed in
4. Sign the CSR with the AK
5. 


https://github.com/google/go-attestation

https://github.com/brandonweeks/acme-device-attest-demo


Use eBPF as an IMA alternative. 

We do the same thing, compute IMA event log, tpm extend into a PCR and then parry to an attestation platform, but we use cgroups to
capture container events

Attack scenario

https://user-images.githubusercontent.com/1120995/66738957-a022d880-eeaa-11e9-8d39-339a11d667d9.png

