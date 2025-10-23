# borromean-ts

This branch is where I implemented liquid range proofs using the variant of borromean ring signatures found in the elements code base.

Run:
```
ts-node messaging-prototype.ts
```

To verify the generated range proof on regtest:
- Run `elements-cli importblindingkey "el1qqfj44uf6v0wffqm5lnapr9rq4j49uzd7fq50djvn25v3ndlj5u8gcgrhu8g45sr6u5eh2gqyvumzy7nxxspk29mdf38fl94st" fff68d254e89c7aeed25b02778e31778641802d426e256dbd703f2dfd932a45a`
- Run `ts-node messaging-prototype.ts`
- Copy the hex blob after "TX2"
- Run `elements-cli unblindrawtransaction <hex_blob>`, replacing `<hex_blob>` with what you copied in the previous step

Decoding the message in the range proof is a bit harder but you can see how I'm doing it in messaging-prototype.ts