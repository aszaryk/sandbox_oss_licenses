# Veracode Sandbox OSS Components and License Info

Script to output OSS components and licenses from latest scan in application sandboxes in Veracode platform

Uses Python3

## Setup

Clone this repository:

    git clone https://github.com/aszaryk/sandbox_oss_licenses

Install dependencies:

    cd sandbox_oss_licenses
    pip3 install -r requirements.txt

(Optional) Save Veracode API credentials in `~/.veracode/credentials`

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

## Usage

Tested using Python3 

usage: get_sandbox_oss_license_info.py applist.txt

NOTE:

--applist.txt is a REQUIRED text file containing application names used in parsing sandboxes.

--Application names should be exact


## Run

If you have saved credentials as above you can run:

    python3 get_sandbox_oss_license_info.py applist.txt
    
Otherwise you will need to set environment variables before running `get_sandbox_oss_license_info.py`:

    export VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    export VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>
    python3 get_sandbox_oss_license_info.py applist.txt
