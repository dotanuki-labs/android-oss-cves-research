#! /bin/sh

set -e

function scan() {
	project=$1
	folder=$2
	commit=$3

	git clone "git@github.com:$project.git" $folder

	cd $folder
	git checkout $commit
	gradle-bodyguard -p .  -d .
	cd ..
}

# commits@HEAD collected at June 4th / 2020

# Demos from Google
scan 'google/santa-tracker-android' 'santa-tracker' 'bac925e399877e268e9faff0c3131befcc70f2e8'
scan 'android/plaid' 'plaid' 'e703957b5e5d4728dea94f11f8d0d27d227f9725'
scan 'android/uamp' 'uamp' '25ff0f3162907ce308246c34319c365746392665'
scan 'google/iosched' 'iosched' '4054aa3f8934b8b1208d5823fdbf531a8eb367af'
scan 'android/sunflower' 'sunflower' 'a4a7cd385f4268680ba1b7f02b162395dc967cf9'

# Mail / messaging
scan 'k9mail/k-9' 'k9mail' '46747bf1140946d0e8804f2bf054e5a6a4931cea'
scan 'Protonmail/proton-mail-android' 'protonmail' '38e2ebf4404d16b0822b73873be3f74a575f7aba'
scan 'wireapp/wire-android' 'wire' '3b9bda898ab77f38bf3ef06435fbe98e25d3f9e7'

# Privacy related
scan 'duckduckgo/Android' 'duckduckgo' '03c57e9a21c6071bd0c2ab4b7b19a44cbe6c28ba'
scan 'signalapp/Signal-Android' 'signal' '26a9dd98c105cb7f5af69ade4d3e51e569a1de7b'

# COVID-related
scan 'corona-warn-app/cwa-app-android' 'corona-warn-app' 'd842f1a80bfca14438f91877cdb8699da8cada79'
scan 'immuni-app/immuni-app-android' 'immuni-app' '04d6db8e1025716fa095719c680ca940c9f8131c'

# Security related
scan 'freeotp/freeotp-android' 'freeotp' 'eb2f12f33a38235433fd83e0ad3eb15affae871f'
scan 'guardianproject/haven' 'haven' '8b8a7d26bc47c3c62a185da82247f8d32e081d6f'
scan 'mozilla-lockwise/lockwise-android' 'mozilla-lockwise' '436557c6c56303b251628c4620f7cc3486a38624'
scan 'WireGuard/wireguard-android' 'wireguard' 'd60efcd7c7acfae583cdb0349dc2ab5ce4ae3824'

# Tools
scan 'termux/termux-app' 'termux' 'b6d7831646bb0ea0223946fdac2f5943610e8118'
scan 'connectbot/connectbot' 'connectbot' '512d1d1bc1d96885f179fde38c54e9ed0c9e253b'

# Misc
scan 'kickstarter/android-oss' 'kickstarter' '759904dd9e14928be84fad01b291d126f52bfed7'
scan 'wordpress-mobile/WordPress-Android' 'wordpress' 'dc41909f75cde15273d366494135ffb918e9a5d1'
scan 'wikimedia/apps-android-wikipedia' 'wikipedia' '8753a053d2ffa22ecf8cff400e1e283e71ff8164'

echo "\nDone. Collected CVEs from all projects.\n"
