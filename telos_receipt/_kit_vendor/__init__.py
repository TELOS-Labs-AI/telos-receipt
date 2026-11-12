"""The kit's own record reader, copied byte for byte: receipt.py, witness.py and reading.py of the kit's h0a/.

tools/vendor_kit_reader.py makes these copies and writes their pin (the kit commit and each file's sha256) into
telos_receipt/record.py. Nothing here is edited by hand, linted, reformatted or imported as a module:
telos_receipt.record hashes the three files, compares them with its pin, and runs exactly the bytes it hashed.
This file is the only one in the directory that is not a copy.
"""
