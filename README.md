# MooCaW

A simple implementation of "Chaffing and Winnowing" (CaW) as proposed by
Ronald L. Rivest.

See: https://people.csail.mit.edu/rivest/chaffing-980701.txt (copy in [doc/](doc))

## Usage

### Encode message

    echo "My message" | py encode.py [secret key] > cypher.txt

### Decode message

    cat cypher.txt | py decode.py [secret key]

### Other options

    py encode.py -h
    py decode.py -h

## Requirements

Python 3.7
