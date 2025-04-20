#!/bin/bash
touch change_log
inotifywait -e create,modify,move,delete --recursive --exclude '/\.' --monitor --format "%e %w%f" / | while read change ;do 
	path=$(echo "$change" | awk '{print $2}') 
	event=$(echo "$change" | awk '{print $1}')
	if [[ "$path" =~ "/sys" || "$path" =~ "/proc" || "$path" =~ "/var/log" || "$path" =~ "/var/tmp" || "$path" =~ "/run" || "$path" =~ "/var/cache" || "$path" =~ "/tmp" || "$path" =~ "/mnt" || "$path" =~ "/home/victim/changed_hashes" || "$path" =~ "/home/victim/change_log" || "$path" =~ "/var/lib" || "$path" =~ "/dev" ]]
	then
	continue
	else
	if [[ -f "$path" && -s "$path" ]]
	then
	md5sum "$path" >> changed_hashes
	else
	echo "$change" >> change_log
	fi
	fi	
done
