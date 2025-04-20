import os
import pytsk3
import hashlib

def read_iocs(filename):
    iocs_64 = set()
    iocs_40 = set()
    with open(filename, 'rb') as f:
        for line in f:
            line = line.strip()
            if len(line) == 64:
                iocs_64.add(line)
            elif len(line) == 40:
                iocs_40.add(line)
    return iocs_64, iocs_40

def calculate_hash(filepath, hash_type):
    try:    
        if hash_type == "SHA256":
            hash_func = hashlib.sha256
        elif hash_type == "SHA1":
            hash_func = hashlib.sha1
        else:
            raise ValueError("Unsupported hash type")

        hash_obj = hash_func()
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                hash_obj.update(chunk)

    except Exception as e:
        print(f"Error calculating hash: {e}")
        return None
    return hash_obj.hexdigest()

def analyse_img(img_path, ioc_hashes, hash_type):
    matches = []
    try:
        img_info = pytsk3.Img_Info(img_path)
    except Exception as e:
        print(f"Error in opening image: {e}")
        return matches

    try:
        vol_info = pytsk3.Volume_Info(img_info)
        for partition in vol_info:
            try:
                fs = pytsk3.FS_Info(img_info, offset=partition.start * 512)
                root_dir = fs.open_dir("/")
                base_dir = root_dir

                def inner_func(base_dir):
                    for entry in base_dir:
                        if entry.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                            inner_func(fs.open_dir(entry.info.name.name))
                        else:
                            file_name = entry.info.name.name.decode('utf-8', 'ignore')
                            file_path = os.path.join("/", file_name)  # file system path inside the image
                            file_hash = calculate_hash(file_path, hash_type)
                            if file_hash and file_hash in ioc_hashes:
                                matches.append(f"{file_name} - {file_path} - {file_hash}")

                inner_func(base_dir)

            except Exception as e:
                print(f"Error in partition {partition.addr}: {e}")

    except Exception as e:
        print(f"Error in volume handling: {e}")
    return matches

def main():
    ioc_file = "sha256_hashes.txt"
    image_path = "disk_image.img"  # Specify the path to the disk image
    hash_type=input("Enter hash type (SHA256 or others): ")
    ioc_file=input("enter the path to ioc file :")
    ioc_sha64, ioc_sha40 = read_iocs(ioc_file)
    if hash_type == "SHA256":
        matches = analyse_img(image_path, ioc_sha64, hash_type) #256
    else:
        matches = analyse_img(image_path, ioc_sha40, hash_type)
    
    print(matches)

