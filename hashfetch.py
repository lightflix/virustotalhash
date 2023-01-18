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
    sha256_list = []
    md5_list = []
    sha1_list = []
    line = "x"

    feed = open("sha256list.txt", "r")

    while True:
        line = feed.readline().strip()
        if not line:
            break
        sha256_list.append(line)

    print(len(sha256_list))
    for hash in sha256_list:

        try:
            repsonse = fetch(hash)
        except:
            print(hash, ":: Not found on virustotal, continuing...")
            continue
        time.sleep(15)

        md5_list.append(repsonse[0])
        sha1_list.append(repsonse[1])
        print("In progress... ")

    print("\n\nMD5: \n")
    for hash in md5_list:
        print(hash)
    
    print("SHA1: \n")
    for hash in sha1_list:
        print(hash)

    with open("hash_result.txt","w") as w:
        for i in range(len(md5_list)):
            w.write(md5_list[i]+"\n")
        for i in range(len(sha1_list)):
            w.write(sha1_list[i]+"\n")
    
main()

