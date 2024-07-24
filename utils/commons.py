
DSCP_CODES = {
    "AF11": 10, "AF12": 12, "AF13": 14,
    "AF21": 18, "AF22": 20, "AF23": 22,
    "AF31": 26, "AF32": 28, "AF33": 30,
    "AF41": 34, "AF42": 36, "AF43": 38,
    "CS0": 0, "CS1": 8, "CS2": 16, "CS3": 24,
    "CS4": 32, "CS5": 40, "CS6": 48, "CS7": 56,
    "EF": 46, "VA": 44
}

DSCP_CODES_NUM = {
    "0":  0,  "1" : 8,  "2": 16,  "3": 24,
    "4":  32, "5" : 40, "6": 48,  "7": 56,
    "11": 10, "12": 12, "13": 14,
    "21": 18, "22": 20, "23": 22,
    "31": 26, "32": 28, "33": 30,
    "41": 34, "42": 36, "43": 38,
    "44": 44, "46": 46  
}

def calculate_bit_operation(tos, reverse = False):  
    # These numbers are bitshifted to the left by two zeros. 
    # So we will be getting them multiplied or divided by four
    
    if reverse:
        return tos/4
    else:
        return tos*4

def get_DSCP_code(value, dictionary = DSCP_CODES):
    return next((key for key, val in dictionary.items() if val == value), None)



