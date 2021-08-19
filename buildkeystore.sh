#!/bin/bash

# Global Variables
runuser=$(whoami)
tempdir=$(pwd)
RED="\033[1;31m"
GREEN="\033[1;32m"
BLUE="\033[1;36m"
YELLOW="\033[1;33m"
NC="\033[0m"
# Echo Title
clear
echo
echo -e "${BLUE}=========================================================================="
echo -e "${BLUE} Cobalt Strike KeyStore builder "
echo -e "${BLUE}=========================================================================="
echo
echo -ne "${YELLOW}[!] Please choose whether to build SSL certs with LetsEncrypt or specify if you have your own signed certificate."
  while : ; do
  echo -e "${YELLOW}"
  echo
  PS3=$'\nPlease select an option: '
  options=("Build SSL certificates with LetsEncrypt" "Use already signed certificate" "Quit")
  select opt in "${options[@]}"
  do
      case $opt in
          "Build SSL certificates with LetsEncrypt")
              echo
              echo
              echo -e "${YELLOW}[!] A DNS record must exist for your domain pointing to this machine."
              echo
              echo -e "${BLUE}Are you sure a DNS record exists? If not, certificate generation will fail."
                  echo -e -n "${NC}"
                  read -e -p "[y]/n: " dnsrecordinput
                  dnsrecordinput=${dnsrecordinput:-y}
                  dnsrecord=$(echo "$dnsrecordinput" | awk '{print tolower($0)}')
                  if [ $dnsrecord == "y" ]; then
                    echo
                    echo
                    echo -e "${BLUE}[*] OK"
                  else
                    echo
                    echo
                    echo -e "${YELLOW}OK. Returning to menu..."
                    break
                  fi


              # Environment Checks

              #Check if running on Debian
              echo
              echo -e "${BLUE}=========================================================================="
              echo -e "${BLUE} Checks "
              echo -e "${BLUE}=========================================================================="
              echo
              func_check_os(){
                echo -e "${BLUE}[*] Checking if running on Debian kernel (needed)."
                if cat /proc/version | grep -i debian 1>/dev/null; then
                  echo
                  echo -e "${GREEN}  [+] Running on Debian kernel."
                  echo
                else
                  echo
                  echo -e "${RED}[-] Error. This script is only meant to run on Debian-based Linux distributions. Exiting."
                  exit 1
                fi
              }

              # Check Sudo Dependency
              func_check_env(){

                if [ $(id -u) -ne '0' ]; then
                  echo
                  echo -e "${RED}[-] This Setup Script Requires root privileges!"
                  echo -e "${RED}    Please run this setup script again with sudo or run as root."
                  echo
                  exit 1
                fi
              }

              # Check for necessary programs to be installed
              func_check_tools(){
                echo -e "${BLUE}[*] Checking for needed applications."
                echo

                #Check for java
                if [ $(which java) ]; then
                  echo -e "${GREEN}  [+] Java is installed."
                else
                  echo
                  echo -e "${RED}  [-] Java does not seem to be installed."
                  echo
                  echo -e "${BLUE}Would you like to install Java?"
                  echo -e -n "${NC}"
                  read -e -p "[y]/n: " installjreinput
                  installjreinput=${installjreinput:-y}
                  installjre=$(echo "$installjreinput" | awk '{print tolower($0)}')
                  if [ $installjre == "y" ]; then
                    echo
                    echo -e "${BLUE}[*] Installing Java"
                    echo -e "${NC}"
                    if apt-get update && apt-get -y install default-jre; then
                      echo
                      echo -e "${GREEN}[+] Installed Java."
                    else
                      echo
                      echo -e "${RED}[-] Error installing Java. Check output or download/install manually and re-run script."
                      exit 1
                    fi
                  else
                    echo -e "{$YELLOW}[!] OK. Install with \"apt update && apt install default-jre\""
                    exit 1
                  fi
                fi

                #Check for Java keytool
                if [ $(which keytool) ]; then
                  echo -e "${GREEN}  [+] Java keytool is installed."
                else
                  echo
                  echo -e "${RED}  [-] Java keytool does not seem to be installed."
                  echo
                  echo -e "${BLUE}Would you like to install Java-jdk?"
                  echo -e -n "${NC}"
                  read -e -p "[y]/n: " installjavainput
                  installjavainput=${installjavainput:-y}
                  installjava=$(echo "$installjavainput" | awk '{print tolower($0)}')
                  if [ $installjava == "y" ]; then
                    echo
                    echo -e "${BLUE}[*] Installing Java-jdk"
                    echo -e "${NC}"
                    if apt-get update && apt-get -y install default-jdk; then
                      echo -n
                    else
                      echo -e "${RED}[-] Error installing Java-jdk. Check output or download/install manually and re-run script."
                      exit 1
                    fi
                  else
                    echo -e "{$YELLOW}[!] OK. Install with \"apt update && apt install default-jdk\""
                    exit 1
                  fi
                fi

                #Check for openssl
                if [ $(which openssl) ]; then
                  echo -e "${GREEN}  [+] OpenSSL is installed."
                else
                  echo
                  echo -e "${RED}  [-] OpenSSL does not seem to be installed. Install manually and re-run script."
                  echo
                  exit 1
                fi

                #Check for git
                if [ $(which git) ]; then
                  echo -e "${GREEN}  [+] Git is installed."
                else
                  echo
                  echo -e "${RED}  [-] Git does not seem to be installed."
                  echo
                  echo -e "${BLUE}Would you like to install Git?"
                  echo -e -n "${NC}"
                  read -e -p "[y]/n: " installgitinput
                  installgitinput=${installgitinput:-y}
                  installgit=$(echo "$installgitinput" | awk '{print tolower($0)}')
                  if [ $installgit == "y" ]; then
                    echo
                    echo -e "${BLUE}[*] Installing Git"
                    echo -e "${NC}"
                    if apt-get update && sudo apt-get -y install git; then
                      echo -n
                    else
                      echo -e "${RED}[-] Error installing Git. Check output or download/install manually and re-run script."
                      exit 1
                    fi
                  else
                    echo -e "{$YELLOW}[!] OK. Install with \"apt update && apt install git\""
                    exit 1
                  fi
                fi

                #Check for certbot
                if [ $(which certbot) ]; then
                  echo -e "${GREEN}  [+] Certbot is installed."
                else
                  echo
                  echo -e "${RED}  [-] Certbot does not seem to be installed."
                  echo
                  echo -e "${BLUE}Would you like to install Certbot and its dependecies?"
                  echo -e -n "${NC}"
                  read -e -p "[y]/n: " installcertinput
                  installcertinput=${installcertinput:-y}
                  installcert=$(echo "$installcertinput" | awk '{print tolower($0)}')
                  if [ $installcert == "y" ]; then
                    echo
                    echo -e "${BLUE}[*] Installing Certbot"
                    func_install_certbot(){
                      echo -e "${BLUE}[*] Checking for snapd"
                      if [ $(which snap) ]; then
                        echo -e "${GREEN}  [+] snap is installed."
                        echo
                      else
                        echo
                        echo -e "${RED}  [-] snapd does not seem to be installed."
                        echo
                        echo -e "${BLUE}[*] Installing snapd."
                        echo -e "${NC}"
                        if apt-get update && apt-get -y install snapd; then
                          echo
                          systemctl start snapd 1>/dev/null
                          echo -e "${GREEN}[+] Installed snapd."
                          echo
                        else
                          echo
                          echo -e "${RED}[-] snapd could not be updated. Check output or install manually with \"apt-get update && apt-get install snapd\" and re-run script."
                          exit 1
                        fi
                      fi
                      echo -e "${BLUE}[*] Updating snapd."
                      echo -e "${NC}"
                      if snap install core && snap refresh core; then
                        echo
                        echo -e "${GREEN}[+] snapd is set up."
                        echo
                      else
                        echo
                        echo -e "${RED}[-] snapd could not be updated. Check output or update manually with \"snap install core && snap refresh core\" and re-run script."
                        exit 1
                      fi
                      echo -e "${BLUE}[*] Starting certbot install"
                      echo -e "${NC}"
                      if snap install --classic certbot; then
                        ln -s /snap/bin/certbot /usr/bin/certbot 2>/dev/null
                        echo
                        echo -e "${GREEN}[+] certbot is set up."
                        echo
                        echo -e "${BLUE}[*] All checks good."
                        echo
                      else
                        echo
                        echo -e "${RED}[-] certbot could not be installed. Check output or install manually with \"snap install --classic certbot\" and re-run script."
                        exit 1
                      fi
                      }
                    func_install_certbot
                  else
                    echo
                    echo -ne "${YELLOW}"
                    echo -e "[!] OK. Install Certbot manually and re-run script."
                    exit 1
                  fi
                fi
              }

	      func_check_os
              func_check_env
              func_check_tools

              func_read_vars(){
                echo
                echo -e "${BLUE}=========================================================================="
                echo -e "${BLUE} Certificate Setup "
                echo -e "${BLUE}=========================================================================="
                echo
                echo -e "${BLUE}Enter the DNS (A) record for your domain"
                echo -e -n "${NC}"
                read -e -p "Domain: " domain
                echo

                echo -e "${BLUE}Enter password to be used for keystore"
                while true; do
                  echo -e -n "${NC}"
                  read -s -p "Password: " password
                  echo
                  echo -e -n "${NC}"
                  read -s -p "Verify Password: " password2
                  echo
                  [ "$password" = "$password2" ] && break
                  echo -e "${RED}[-]Password mismatch, please try again."
                done
                echo
                echo -e "${BLUE}Enter full path to your CobaltStrike server (/path/to/folder)"
                while true; do
                   echo -e -n "${NC}"
                   read -e -p "Path: " cobaltStrikeinput
                   cobaltStrike=$(echo $cobaltStrikeinput | sed -s 's:/*$::')
                   if [ -f "$cobaltStrike/teamserver" ]
                   then
                     break
                   else
                     echo -e "${RED}[-] Cannot find CobaltStrike teamserver in specified path. Please try again."
                   fi
                done
                echo

                domainPkcs="$domain.p12"
                domainStore="$domain.store"
                cobaltStrikeProfilePath="$cobaltStrike/c2profiles"
              }

              func_build_cert(){
                echo -e "${BLUE}[*] Requesting LetsEncrypt certificate"
                echo -e "${NC}"
                certbot certonly --standalone -d $domain -n --register-unsafely-without-email --agree-tos
                if [ -f /etc/letsencrypt/live/$domain/fullchain.pem ]; then
                  echo
                  echo "${GREEN}[+] Success. LetsEncrypt certs are built!"
                else
                  echo
                  if ls -1 /etc/letsencrypt/live/$domain/*.pem 2>/dev/null | grep pem; then
                    echo
                    echo -e "${YELLOW}[!] It looks like certificates were built, try and re-run the script with option 2 and specify these file paths."
                    echo -e "${NC}"
                    ls -1 /etc/letsencrypt/live/$domain/*.pem
                    echo
                  else
                    echo
                    echo -e "${RED}No certificate file found. Look at certbot output above."
                    echo "Check that DNS records are properly configured for this domain."
                    echo
                    exit 1
                  fi
                fi
                cd /etc/letsencrypt/live/$domain
                echo
                echo -e "${BLUE}[*] Building PKCS12 .p12 cert."
                if openssl pkcs12 -export -in fullchain.pem -inkey privkey.pem -out $domainPkcs -name $domain -passout pass:$password
                then
                  echo -e "${GREEN}  [+] Built $domainPkcs PKCS12 cert."
                  echo
                else
                  echo
                  echo -e "${RED} [-] Error building cert. Check output."
                  exit 1
                fi
                echo -e "${BLUE}[*] Building Java keystore via keytool."
                echo -e -n "${NC}"
                if keytool -importkeystore -deststorepass $password -destkeypass $password -destkeystore $domainStore -srckeystore $domainPkcs -srcstoretype PKCS12 -srcstorepass $password -alias $domain
                then
                  rm $domainPkcs
                  echo -e "${GREEN}  [+] Java keystore $domainStore built."
                  echo
                else
                  echo
                  echo -e "${RED}[-] Error building Java keystore. Check output."
                  rm $domainPkcs
                  exit 1
                fi
                if [ ! -d $cobaltStrikeProfilePath ]
                then
                  echo -e "${BLUE}[*] Creating directory $cobaltStrikeProfilePath"
                  mkdir $cobaltStrikeProfilePath
                  echo -e "${GREEN}  [+] Directory $cobaltStrikeProfilePath created."
                else
                  echo -e "${BLUE}[*] Moving keystore file"
                fi
                mv $domainStore $cobaltStrikeProfilePath
                echo -e "${GREEN}  [+] Moved Java keystore as \"$domainStore\" to $cobaltStrikeProfilePath"
                echo
              }

              func_build_c2profile(){
                echo
                echo -e "${BLUE}Would you like to create an https C2 profile using the created keystore?"
                echo -e -n "${NC}"
                read -e -p "[y]/n: " createprofileinput
                createprofileinput=${createprofileinput:-y}
                createprofile=$(echo "$createprofileinput" | awk '{print tolower($0)}')
                if [ $createprofile == "y" ]
                  then
                  echo
                  cd $cobaltStrikeProfilePath
                  echo -e "${BLUE}[*] Cloning jQuery profile from ThreatExpress"
                  echo
                  echo -e -n "${NC}"
                  if wget https://raw.githubusercontent.com/threatexpress/malleable-c2/master/jquery-c2.4.3.profile --no-check-certificate -O jquery.$domain.profile; then
                     echo
                     echo -e "${GREEN}[+] jQuery profile cloned."
                     sed -i "s~^.*#set keystore.*~\tset keystore \"$cobaltStrikeProfilePath/$domainStore\";~g" jquery.$domain.profile
                     sed -i "s/^.*#set password.*/\tset password \"$password\";/g" jquery.$domain.profile
                     sed -i 's/^.*set C   \"US\";/\t#set C   \"US\";/g' jquery.$domain.profile
                     sed -i 's/^.*set CN  \"jquery.com\";/\t#set CN  \"jquery.com\";/g' jquery.$domain.profile
                     sed -i 's/^.*set O   \"jQuery\";/\t#set O   \"jQuery\";/g' jquery.$domain.profile
                     sed -i 's/^.*set OU  \"Certificate Authority\";/\t#set OU  \"Certificate Authority\";/g' jquery.$domain.profile
                     sed -i 's/^.*set validity \"365\";/\t#set validity \"365\";/g' jquery.$domain.profile
                     echo -e "${GREEN}[+] Added java keystore / password to jQuery profile."
                     echo
                     echo -e "${BLUE}[*] Verifying profile with c2lint"
                     cd $cobaltStrike
                     ./c2lint $cobaltStrikeProfilePath/jquery.$domain.profile
                     echo
                     echo
                     echo -e "${GREEN}[+] Finished running checks on profile. Look for errors or warnings."
                     echo -e "${YELLOW}[!] It is also good practice to review the generated profile and tweak settings to make C2 comms more unqiue and less detectable."
                     echo
                     echo -e "${GREEN}[+] C2 profile created:"
                     echo -e "${NC} $cobaltStrikeProfilePath/jquery.$domain.profile"
                  else
                     echo -e "${RED}[-] Could not clone profile. Are you connected to the web?"
                  fi
                else
                  echo
                  echo -e "${BLUE}OK"
                fi
                echo
                echo
                echo -e "${GREEN}[+] KEYSTORE BUILT SUCCESSFULLY!"
                echo -e "${GREEN}[+] Location:"
                echo -e "${NC} $cobaltStrikeProfilePath/$domainStore"
                echo
                echo
                echo -e "${NC} NOTE:"
                echo
                echo -e "${NC} You can use the created keystore \"$domainStore\" as the Teamserver SSL certificate by modifying the teamserver script and"
                echo -e "${NC} changing values of \"-Djavax.net.ssl.keyStore=\" and \"-Djavax.net.ssl.keyStorePassword=\""
                echo -e "${NC} Additionally this keystore can be used in Malleable C2 SSL profiles (highly recommend) by specifying the following characteristics in your custom profile:"
                echo
                echo -e "${NC} https-certificate {"
                echo -e "${NC}         set keystore \"$cobaltStrikeProfilePath/$domainStore\";"
                echo -e "${NC}         set password \"<password>\";"
                echo -e "${NC} }"
                echo
                cd $tempdir
                exit 1
              }

              func_read_vars
              func_build_cert
              func_build_c2profile
              ;;

          "Use already signed certificate")

              # Environment Checks

              #Check if running on Debian
              echo
              echo -e "${BLUE}=========================================================================="
              echo -e "${BLUE} Checks "
              echo -e "${BLUE}=========================================================================="
              echo
              func_check_os(){
                echo -e "${BLUE}[*] Checking if running on Debian kernel (needed)."
                if cat /proc/version | grep -i debian 1>/dev/null; then
                  echo
                  echo -e "${GREEN}  [+] Running on Debian kernel."
                  echo
                else
                  echo
                  echo -e "${RED}[-] Error. This script is only meant to run on Debian-based Linux distributions. Exiting."
                  exit 1
                fi
              }

              func_check_env(){
                # Check Sudo Dependency going to need that!
                if [ $(id -u) -ne '0' ]; then
                  echo
                  echo -e "${RED}[-] This Setup Script Requires root privileges!"
                  echo -e "${RED}    Please run this setup script again with sudo or run as root."
                  echo
                  exit 1
                fi
              }

              func_check_tools(){
                # Check Sudo Dependency going to need that!
                 echo -e "${BLUE}[*] Checking for needed applications to be installed"
                 echo
                if [ $(which keytool) ]; then
                  echo -e "${GREEN}  [+] Java keytool is installed."
                else
                  echo
                  echo -e "${RED}  [-] java keytool does not seem to be installed."
                  echo
                  echo -e "${BLUE}Would you like to install Java?"
                  echo -e -n "${NC}"
                  read -e -p "[y]/n: " installjavainput
                  installjavainput=${installjavainput:-y}
                  installjava=$(echo "$installjavainput" | awk '{print tolower($0)}')
                  if [ $installjava == "y" ]; then
                     echo
                     echo -e "${BLUE}[*] Installing java"
                     echo -e "${NC}"
                     if apt-get update && apt-get -y install default-jdk; then
                        echo -n
                     else
                        echo -e "${RED}[-] Error installing java. Check output or download/install manually and re-run script."
                        exit 1
                     fi
                  else
                     echo -e "{$BLUE}[*] OK. Install with \"apt update && apt install default-jdk\""
                     exit 1
                  fi
                fi
                if [ $(which openssl) ]; then
                  echo -e "${GREEN}  [+] OpenSSL is installed."
                  echo
                else
                  echo
                  echo -e "${RED}  [-] OpenSSL does not seem to be installed. Install manually and re-run script."
                  echo
                  exit 1
                fi
              }
              func_check_os
              func_check_env
              func_check_tools

              func_read_vars(){
                echo
                echo -e "${BLUE}=========================================================================="
                echo -e "${BLUE} Certificate Setup "
                echo -e "${BLUE}=========================================================================="
                echo
                echo -e "${BLUE}Enter the DNS (A) record for your domain"
                echo -e -n "${NC}"
                read -e -p "Domain: " domain
                echo
                echo -e "${BLUE}Enter password to be used for keystore"
                while true; do
                  echo -e -n "${NC}" 
                  read -s -p "Password: " password
                  echo
                  echo -e -n "${NC}"
                  read -s -p "Verify Password: " password2
                  echo
                  [ "$password" = "$password2" ] && break
                  echo -e "${RED}[-]Password mismatch, please try again."
                done
                echo

                echo -e "${BLUE}Enter full path to your CobaltStrike server (/path/to/folder)"
                while true; do
                   echo -e -n "${NC}"
                   read -e -p "Path: " cobaltStrikeinput
                   cobaltStrike=$(echo $cobaltStrikeinput | sed -s 's:/*$::')
                   if [ -f "$cobaltStrike/teamserver" ]
                   then
                     break
                   else
                     echo -e "${RED}[-] Cannot find CobaltStrike teamserver in specified path. Please try again."
                   fi
                done
                echo
                echo -e "${BLUE}Enter full path to your certificate chain (/path/to/chain.pem)"
                while true; do
                   echo -e -n "${NC}"
                   read -e -p "Path: " fullchain
                   if [ -f $fullchain ]
                   then
                     break
                   else
                     echo -e "${RED}[-] Cannot find certificate chain. Please try again."
                   fi
                done
                echo
                echo -e "${BLUE}Enter full path to your cetificate private key file (/path/to/key.pem)"
                while true; do
                   echo -e -n "${NC}"
                   read -e -p "Path: " privkey
                   if [ -f $privkey ]
                   then
                     break
                   else
                     echo -e "${RED}[-] Cannot find private key. Please try again."
                   fi
                done
                echo

                domainPkcs="$domain.p12"
                domainStore="$domain.store"
                cobaltStrikeProfilePath="$cobaltStrike/c2profiles"
              }

              func_build_pkcs(){
                echo -e "${BLUE}[*] Building PKCS12 .p12 cert."
                if openssl pkcs12 -export -in $fullchain -inkey $privkey -out $domainPkcs -name $domain -passout pass:$password; then
                   echo -e "${GREEN}  [+] Built $domainPkcs PKCS12 cert."
                   echo
                else
                   echo
                   echo -e "${RED} [-] Error building cert. Check output."
                   exit 1
                fi
                echo -e "${BLUE}[*] Building Java keystore via keytool."
                echo -e -n "${NC}"
                if keytool -importkeystore -deststorepass $password -destkeypass $password -destkeystore $domainStore -srckeystore $domainPkcs -srcstoretype PKCS12 -srcstorepass $password -alias $domain; then
                   rm $domainPkcs
                   echo -e "${GREEN}  [+] Java keystore $domainStore built."
                   echo
                else
                   echo
                   echo -e "${RED}[-] Error building Java keystore. Check output."
                   rm $domainPkcs
                   exit 1
                fi
                if [ ! -d $cobaltStrikeProfilePath ]
                then
                  echo -e "${BLUE}[*] Creating directory $cobaltStrikeProfilePath"
                  mkdir $cobaltStrikeProfilePath
                  echo -e "${GREEN}  [+] Directory $cobaltStrikeProfilePath created."
                else
                  echo -e "${BLUE}[*] Moving keystore file"
                fi
                mv $domainStore $cobaltStrikeProfilePath
                echo -e "${GREEN}  [+] Moved Java keystore as \"$domainStore\" to $cobaltStrikeProfilePath"
                echo
              }

              func_build_c2profile(){
                echo
                echo -e "${BLUE}Would you like to create an https C2 profile using the created keystore?"
                echo -e -n "${NC}"
                read -e -p "[y]/n: " createprofileinput
                createprofileinput=${createprofileinput:-y}
                createprofile=$(echo "$createprofileinput" | awk '{print tolower($0)}')
                if [ $createprofile == "y" ]; then
                  echo
                  cd $cobaltStrikeProfilePath
                  echo -e "${BLUE}[*] Cloning jQuery profile from ThreatExpress"
                  echo
                  echo -e -n "${NC}"
                  if wget https://raw.githubusercontent.com/threatexpress/malleable-c2/master/jquery-c2.4.3.profile --no-check-certificate -O jquery.$domain.profile; then
                     echo
                     echo -e "${GREEN}[+] jQuery profile cloned."
                     sed -i "s~^.*#set keystore.*~\tset keystore \"$cobaltStrikeProfilePath/$domainStore\";~g" jquery.$domain.profile
                     sed -i "s/^.*#set password.*/\tset password \"$password\";/g" jquery.$domain.profile
                     sed -i 's/^.*set C   \"US\";/\t#set C   \"US\";/g' jquery.$domain.profile
                     sed -i 's/^.*set CN  \"jquery.com\";/\t#set CN  \"jquery.com\";/g' jquery.$domain.profile
                     sed -i 's/^.*set O   \"jQuery\";/\t#set O   \"jQuery\";/g' jquery.$domain.profile
                     sed -i 's/^.*set OU  \"Certificate Authority\";/\t#set OU  \"Certificate Authority\";/g' jquery.$domain.profile
                     sed -i 's/^.*set validity \"365\";/\t#set validity \"365\";/g' jquery.$domain.profile
                     echo -e "${GREEN}[+] Added java keystore / password to jQuery profile."
                     echo
                     echo -e "${BLUE}[*] Verifying profile with c2lint"
                     cd $cobaltStrike
                     ./c2lint $cobaltStrikeProfilePath/jquery.$domain.profile
                     echo
                     echo
                     echo -e "${GREEN}[+] Finished running checks on profile. Look for errors or warnings."
                     echo -e "${YELLOW}[!] It is also good practice to review the generated profile and tweak settings to make C2 comms more unqiue and less detectable."
                     echo
                     echo -e "${GREEN}[+] C2 profile created:"
                     echo -e "${NC} $cobaltStrikeProfilePath/jquery.$domain.profile"
                  else
                     echo -e "${RED}[-] Could not clone profile. Are you connected to the web?"
                  fi
                else
                  echo
                  echo -e "${BLUE}OK"
                fi
                echo
                echo
                echo -e "${GREEN}[+] KEYSTORE BUILT SUCCESSFULLY!"
                echo -e "${GREEN}[+] Location:"
                echo -e "${NC} $cobaltStrikeProfilePath/$domainStore"
                echo
                echo
                echo -e "${YELLOW}[!] NOTE:"
                echo
                echo -e "${NC} You can use the created keystore \"$domainStore\" as the Teamserver SSL certificate by modifying the teamserver script and"
                echo -e "${NC} changing values of \"-Djavax.net.ssl.keyStore=\" and \"-Djavax.net.ssl.keyStorePassword=\""
                echo -e "${NC} Additionally this keystore can be used in Malleable C2 SSL profiles (highly recommend) by specifying the following characteristics in your custom profile:"
                echo
                echo -e "${NC} https-certificate {"
                echo -e "${NC}         set keystore \"$cobaltStrikeProfilePath/$domainStore\";"
                echo -e "${NC}         set password \"<password>\";"
                echo -e "${NC} }"
                echo
                cd $tempdir
                exit 1
              }

              func_read_vars
              func_build_pkcs
              func_build_c2profile
              ;;
          "Quit")
              exit 1
              ;;
          *) echo "Invalid option";;
      esac
  done
done


