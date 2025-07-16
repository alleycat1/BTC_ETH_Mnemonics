# bitcoin-wallgen
A Go program designed to create private keys, derive corresponding public keys from the private keys, and then check that the generated wallet addresses are matched with the richlist.

# how to use
This software requires the correct 12 mnemonics in the "mnemonics.txt", You can input or update the mnemonics in this file.

Run with normal mode:
  ./start_btc_walletscan.bat
  ./start_eth_walletscan.bat
  ./walletscan.exe

Extended mode: You can change the parameters in these files.
  ./start_btc_walletscan.bat
  ./start_eth_walletscan.bat

Parameters:
  type - BTC: 0, ETH: 1
  workers - Thread count working parallely,
  wallets - File name containing the richlist

Result:
  When it finds the matched address, then it will show the corresponding adddress, save priavte key information into the file named with same as the matched address.