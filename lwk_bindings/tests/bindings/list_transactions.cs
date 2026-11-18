// This is tested separetely, not tested with uniffi test-framework

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

using uniffi.lwk;

class Program
{
    static void Main(string[] args)
    {
        Network network = Network.Testnet();
        Console.WriteLine(network);

        Mnemonic mnemonic = new Mnemonic("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
        Console.WriteLine(mnemonic);

        Signer signer = new Signer(mnemonic, network);
        WolletDescriptor desc = signer.WpkhSlip77Descriptor();
        Console.WriteLine(desc);

        Wollet wollet = new Wollet(network, desc, null);

        // A wallet that has not scanned has no transactions. The default
        // Electrum server of this network serves Liquid, whose blocks
        // Sequentia's wire format cannot read, so nothing here goes online.
        WalletTx[] txList = wollet.Transactions();

        Console.WriteLine("Transactions {0}:", txList.Length);

        if (txList.Length != 0) {
            throw new Exception("a wallet that has not scanned lists no transactions");
        }
    }
}
