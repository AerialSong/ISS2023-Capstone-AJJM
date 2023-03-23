#!/bin/bash
read -p "Please input full path to logs you would like to send: " files_location
echo "Path: $files_location"
now_time=$(date +"%H%M%S")
contentType="application/x-compressed-tar"
dateValue=`date -R`

# your key goes here..
echo "Please enter your AWS key:"
read s3Key
echo "Please enter your Secret AWS key:"
read s3Secret

#Asks user if they have a bucket or want to make one
echo "Do you want to create a new S3 bucket or use an existing one?"
select option in "Create new bucket" "Use existing bucket"; do
    case $option in
        "Create new bucket" )
            echo "Please enter a name for your new S3 bucket:"
            read bucket
            aws s3 mb s3://$bucket --region us-east-1 --profile default
            break
            ;;
        "Use existing bucket" )
            echo "Please enter the name of your existing S3 bucket:"
            read bucket
            break
            ;;
        * )
            echo "Invalid option selected."
            ;;
    esac
done

echo "Your AWS key is: $s3Key"
echo "Your Secret AWS key is: $s3Secret"
echo "Your chosen S3 bucket name is: $bucket"

aws configure set aws_access_key_id $s3Key
aws configure set aws_secret_access_key $s3Secret
aws configure set default.s3.bucket $bucket

echo "Credential saved successfully." 

function pushToS3()
{
  files_path=$1
  for file in $files_path*
  do
    fname=$(basename $file)
    resource="/${bucket}/${now_date}/${fname}_${now_time}"
    stringToSign="PUT\n\n${contentType}\n${dateValue}\n${resource}"
    signature=`echo -en ${stringToSign} | openssl sha1 -hmac ${s3Secret} -binary | base64`
    curl -X PUT -T "${file}" \
     -H "Host: ${bucket}.s3.amazonaws.com" \
     -H "Date: ${dateValue}" \
     -H "Content-Type: ${contentType}" \
     -H "Authorization: AWS ${s3Key}:${signature}" \
      https://${bucket}.s3.amazonaws.com/${now_date}/${fname}_${now_time}
  done
  echo "logs sent to S3!"
}

function delete_txt_files() {
   # Prompt the user for the file path
	echo "Enter the path to packetlogs folder: "
	read path

	# Verify that the path is valid
	if [[ ! -d $path ]]; then
		echo "Error: Invalid path."
		exit 1
	fi

	# Ask the user if they want to delete .txt files in the folder
	echo "Would you like to delete all .txt files in the folder? (y/n)"
	read answer

	if [[ $answer == "y" ]]; then
		# Delete all .txt files in the folder
		echo "Deleting all .txt files in the folder..."
		find $path -type f -name "*.txt" -delete
		echo "Done."
	elif [[ $answer == "n" ]]; then
		# Exit the script if the user doesn't want to delete any files
		echo "Exiting without deleting any files."
		exit 0
	else
		# If the user enters an invalid response, exit with an error
		echo "Error: Invalid response. Please enter y or n."
		exit 1
	fi
}
pushToS3 $files_location
delete_txt_files