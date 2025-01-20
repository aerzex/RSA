import random
import sys 
import os
import math
import json
lib_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'algorithms'))
sys.path.append(lib_path)
from algorithms import algorithm_fast_pow, algorithm_euclid_extended, algorithm_Miller_Rabin_test