import numpy as np


class AES:
    def __init__(self, cipher_key):
        self.cipher_key = cipher_key
        self.sbox = [
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        ]
        self.rcon = [
            [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        ]
        self.galiosMatrix = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]
        ]
        self.round = 1
        self.staticKey = cipher_key

    @staticmethod
    def shift(row, amount):
        """
        Used in shift rows
        """
        return row[amount:] + row[0:amount]

    @staticmethod
    def xor(var1, var2):
        """
        Mainly used in addRoundKey
        """
        return var1 ^ var2

    @staticmethod
    def galoisMult(a, b):
        """
        Used in mixColumns
        """
        p = 0
        hi_bit_set = 0
        for i in range(8):
            if b & 1 == 1: p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set == 0x80: a ^= 0x1b
            b >>= 1
        return p % 256

    def addRoundKey(self, plain_text, round_key):
        """
        Add round key stage of AES
        """
        for i in range(len(round_key)):
            for j in range(len(round_key[0])):
                plain_text[i][j] = self.xor(plain_text[i][j], round_key[i][j])

    def shiftRows(self, matrix):
        """
        Shift Rows stage of AES
        """
        for i in range(len(matrix)):
            matrix[i] = self.shift(matrix[i], i)

    def mixColumns(self, matrix):
        """
        Mix Column Stage of AES
        """
        result = np.array([[0] * 4] * 4)
        for i in range(len(self.galiosMatrix)):
            for j in range(len(matrix[0])):
                for k in range(len(matrix)):
                    a = self.galoisMult(self.galiosMatrix[i][k], matrix[k][j])
                    he = hex(a)
                    result[i][j] ^= a
        return result.tolist()

    def initial_round(self, state):
        self.addRoundKey(state, self.staticKey)
        return state

    def returnColumn(self, matrix, n):
        """
        Returns the column number in the form of 1D array
        """
        column = []
        for i in range(len(matrix)):
            row = i
            col = n - 1
            a = matrix[i][n - 1]
            column.append(a)
        return column

    def fillColumn(self, matrix, n, column):
        """
        Fills the nth column of matrix with the values in the array [column]
        """
        matrix = np.array(matrix)
        for i in range(4):
            a = column[i]
            for j in range(4):
                if j == n - 1:
                    matrix[i][j] = a
        return matrix.tolist()

    def subBytes(self, column):
        """
        Uses the S box
        """
        for i in range(len(column)):
            column[i] = self.sbox[column[int(i)]]

    def formColumn(self, column1, column2, column):
        """
        Calculates XOR with the column formed and the column in the previous cipher key
        """
        rcon_cur = self.returnColumn(self.rcon, self.round)
        temp = [None] * 4
        for i in range(4):
            if column == 0:
                temp[i] = column1[i] ^ column2[i] ^ rcon_cur[i]
            else:
                temp[i] = column1[i] ^ column2[i]
        return temp

    def generateKey(self):
        MasterKeyList = [self.cipher_key]
        temp = [[None] * 4] * 4
        for i in range(10):
            # To form the first column of the next round cipher key
            column4 = self.returnColumn(self.cipher_key, 4)
            # rot word
            column4 = self.shift(column4, 1)
            # substitute
            self.subBytes(column4)
            # column 1
            column1 = self.returnColumn(self.cipher_key, 1)
            column1 = self.formColumn(column4, column1, 0)
            temp = self.fillColumn(temp, 1, column1)

            for i in range(3):
                col1 = self.returnColumn(temp, i + 1)
                col2 = self.returnColumn(self.cipher_key, i + 2)
                col = self.formColumn(col1, col2, i + 3)
                temp = self.fillColumn(temp, i + 2, col)

            MasterKeyList.append(temp)
            self.cipher_key = temp
            temp = [[None] * 4] * 4
            self.round += 1
        return MasterKeyList

    def execute(self, MasterKeyList, plain_text):
        round = 0
        cipher_text = []
        while round <= 1:
            if round == 0:
                cipher_text = self.initial_round(plain_text)
            else:
                for i in range(len(cipher_text)):
                    for j in range(len(cipher_text[0])):
                        cipher_text[i][j] = self.sbox[int(cipher_text[i][j])]

                self.shiftRows(cipher_text)
                if round != 10:
                    cipher_text = self.mixColumns(cipher_text)

                self.addRoundKey(cipher_text, MasterKeyList[round])
            round += 1
        return cipher_text


cipher_key = [
    [0x3f, 0x65, 0xdf, 0xf4],
    [0x01, 0xa3, 0xf4, 0xc2],
    [0x55, 0x34, 0x21, 0x02],
    [0x24, 0xa3, 0xf4, 0xc2]
]

plain_text = [
    [0x02, 0x56, 0xfd, 0x4f],
    [0x10, 0x3a, 0x4f, 0x2c],
    [0x55, 0x43, 0x12, 0x20],
    [0x42, 0x3a, 0x4f, 0x2c]
]
print("Cipher Key : \n\n", np.array(cipher_key), "\n")
print("Plain Text: \n\n", np.array(plain_text), "\n")
aes = AES(cipher_key)
list = aes.generateKey()
o_p = aes.execute(list, plain_text)
print("Encrypted Output : \n")
for i in range(4):
    for j in range(4):
        if j !=0 and j % 3 == 0:
            print(hex(o_p[i][j]))
        else:
            print(hex(o_p[i][j]), end=" ")
