__author__ = 'rotlogix'

import string
import random


class Generator:

    def __init__(self, size=8, chars=string.ascii_lowercase + string.digits):

        self.size = size
        self.chars = chars

    def generate(self):

        value = ''.join(random.choice(self.chars) for _ in range(self.size))
        return value

