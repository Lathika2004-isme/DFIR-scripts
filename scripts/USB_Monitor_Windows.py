import platform
import wmi
import re
import time
from watchdog.observers import Observer
from watchdog.events import DirModifiedEvent, FileModifiedEvent, FileSystemEventHandler
import hashlib
import datetime
os=platform.system()
print(os)
#for windows
fi1="known.txt"
fi2="current.txt"
new_ones="new_ones.txt"
class MyHandler(FileSystemEventHandler):
	def on_modified(self, event):
		self.clock=0
		time.sleep(1)
		self.hash_function=hashlib.sha256()
		with open(event.src_path,'rb') as f:
			for chunk in iter(lambda: f.read(4096),b""):
				self.hash_function.update(chunk)
			f.close()
		self.hash_val=self.hash_function.hexdigest()
		#print("hex digest value :",temp)
		with open("log.txt",'r') as f:
			self.con=f.read()
			if self.hash_val in self.con:
				self.clock=1
		with open("log.txt",'a') as f:
			if self.clock==0:
				f.write(event.src_path+" "+self.hash_val+" "+str(datetime.datetime.now())+"\n")
				#print("inside the writing fun",hash_function.hexdigest())
			f.close()
def start_observer(path, handler):
    observer = Observer()
    observer.schedule(handler, path, recursive=True)
    observer.start()
    return observer

with open(fi1,'w') as f:
	f.write("")
	f.close()
with open(new_ones,'w') as f:
	f.write("")
	f.close()
known=""
pattern=re.compile(r'USB.+\\.+')
not_caption=["MediaTek Bluetooth Adapter" , "Volume" , "USB Root Hub (USB 3.0)" , "HP Wide Vision HD Camera" , "USB Composite Device" , "USB Mass Storage Device"]
yes_class=["USB","WPD","DiskDrive"]
obj=wmi.WMI()	

def  find_disk(snum):
	disk_num=''
	temp=wmi.WMI()
	for disk in temp.Win32_DiskDrive():
		if snum==disk.SerialNumber:
			temp=disk.DeviceID.split("PHYSICALDRIVE")[1]
			disk_num="Disk #"+temp
			#print(disk_num)
	return disk_num

def find_partition(d_num):
	temp=wmi.WMI()
	for partition in temp.Win32_DiskPartition():
		if partition.DeviceID.startswith(d_num):
			for logical_partition in partition.associators("Win32_LogicalDiskToPartition"):
				return logical_partition.DeviceID+"\\"
	return None

def for_windows():
	usb_devices=[]
	for dev in obj.win32_PnPEntity():
		if pattern.search(dev.PNPDeviceID) and dev.PNPClass in yes_class and dev.Service == "disk":
			if dev.Caption in not_caption:
				continue
			else:
				serial_number=dev.PNPDeviceID.split("\\")[2].split("&")[0]
				usb_devices.append(serial_number+"\n")
	return usb_devices

def main():
	try:
		if os == "Windows" :
			handler=MyHandler()
			observers=[]
			drive_letter=[]
			flag=0
			i=''
			j=''
			a=""
			st=""
			k=0
			l=0
			temp=for_windows()
			known=set()
			with open('db','a') as f:
				for i in temp:
					s=i.split("\n")[0]
					i=find_disk(s)
					print(i)
					j=find_partition(i)
					print(j)
					f.write(s+" "+j+" "+" "+str(datetime.datetime.now())+"\n")
				f.close()

			while True:
				#ch=int(input("enter the choice regarding observer"))
				time.sleep(5)
				current=set(for_windows())
				new=current-known
				known=current
				for i in new:
					a+=i
				if len(a) != 0 :
					with open(new_ones,'r') as f:
						if a in f:
							flag=1
						f.close()
					with open(new_ones,'a') as f:
						if flag!=1:
							f.write(a)
						f.close()

					if len(new) != 0 :
						print("new device is inserted")
					print("new submit",a)
					known.add(a)
					print(known)
					if len(new) != 0:
						drive_letter=[]
						with open(new_ones,'r') as f:
							for line in f.readlines():
								if line != "\n":
									i=find_disk(line.split("\n")[0]) #disk number
									print("printing disk number :",i)
									j=find_partition(i) #drive letter
									print("printing drive letter :",j)
									drive_letter.append(j)
									print("printing arrray...",drive_letter)
									with open('db','r') as f:
										t=f.read()
										f.close()
									with open('db','a') as f1:
										string=line.split('\n')[0]+" "+j+" "+str(datetime.datetime.now())+"\n"
										string2=line.split('\n')[0]+" "+j
										if  string2 not in t:
											f1.write(string)
										f1.close()
						f.close
						#print("all the serial numbers are taken from the new_ones file and drive letter are calculated!")
						print("drive letter",drive_letter)
						if k==0:
							known_letter=drive_letter
							k=k+1
							for letter in known_letter:
								obs=start_observer(letter,handler)
								observers.append(obs)

						else:
							for i in drive_letter:
								if i not in known_letter:
									obs=start_observer(i,handler)
									observers.append(obs)
									known_letter.append(i)
						print("knwon letter ",known_letter)
					a=""
				else:
					print('no device is inserted')
					#print(observers)
	except KeyboardInterrupt:
		for observer in observers:
			observer.stop()
		for observer in observers:
			observer.join()


		
			
			
			
