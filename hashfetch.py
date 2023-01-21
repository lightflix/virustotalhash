#This script fetches MD5 and SHA-1 hashes for corresponding SHA-256 hashes from the file sha256list.txt; Made by https://github.com/lightflix
import vt
import time

with open("apikey.txt", "r") as f:
    apikey = f.readline().strip()

client = vt.Client(apikey)

def fetch(sha256hash):
    response = client.get_object("/files/"+sha256hash)
    return [response.md5, response.sha1]

def main():

    print("\n\n\t-== Virustotal Hash Fetcher v1.0 ==-\n\t\t  by lightflix\n\n")
    sha256_list = []
    md5_list = []
    sha1_list = []
    # valid_hex = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "A", "B", "C", "D", "E", "F"]
    valid_hex = set('0123456789ABCDEF')

    try:
        feed = open("sha256list.txt", "r")
    except:
        print("\n[❌] Error: \"sha256list.txt\" not found. Create the file, add input SHA256 input hashes, save it and try again.")
        time.sleep(11)
        exit()

    while True:
        line = feed.readline().strip()
        line_length = len(line)
        if not line:
            break
        elif(not(line_length == 32 or line_length == 40 or line_length == 64) or any((c.upper() not in valid_hex) for c in line)):
            print("\n❌ Error: Hash is invalid, input valid hash and try again: "+line)
            time.sleep(11)
            exit()
        sha256_list.append(line)

    print("Hashes found in file: "+str(len(sha256_list)))
    print("ETA: "+str(int(len(sha256_list)*15/60))+" mins")

    for hash in sha256_list:

        try:
            repsonse = fetch(hash)
            print("\tIn progress... ", end="\r")
        except:
            print("\t⚠️  "+hash+" - Not found")
            continue
        time.sleep(15)

        print("\t✅  "+hash+" - Success")

        md5_list.append(repsonse[0])
        sha1_list.append(repsonse[1])


    # print("\n\nMD5: \n")
    # for hash in md5_list:
    #     print(hash)
    
    # print("SHA1: \n")
    # for hash in sha1_list:
    #     print(hash)

    with open("hash_result.txt","w") as w:
        for i in range(len(md5_list)):
            w.write(md5_list[i]+"\n")
        for i in range(len(sha1_list)):
            w.write(sha1_list[i]+"\n")

    print("\n\nHashes written to hash_result.txt\n")
    
main()

