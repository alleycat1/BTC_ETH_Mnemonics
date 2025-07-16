# bitcoin-wallgen
A Go program designed to create private keys, derive corresponding public keys from the private keys, and then check that the generated wallet addresses are matched with the richlist.

# how to use
This software requires the correct 12 mnemonics in the "mnemonics.txt", You can input or update the mnemonics in this file.

And start the application with running these files.

Normal mode: 4 threads for BTC wallet generation, and load richlist in the btc.txt
  ./walletscan.exe
  ./walletscan.bat

Extended mode: You can change the parameters in this file.
  ./walletscan.bat

Parameters:
  type - BTC: 0, ETH: 1
  workers - Thread count working parallely,
  wallets - File name containing the richlist

Result:
  When it finds the matched address, then it will show the corresponding adddress, save priavte key information into the file named with same as the matched address.