
Due to BMW newer models (2004+) having much difficulty in modifications,
The attached resources make the process easier for newer models. Below resources
help for tuning and flashing ms54 and ms45.1 dmes BMW's.

Uses Ediabaslib for communications. If you have a functional INPA install, you shouldn't have to mess with anything else. If you don't have ediabas installed, you'll need to grab a copy of ms450ds0.prg and make a couple edits to the config file.

Allows you to read and write full and partial binaries on the MS45.0 and MS45.1 DMEs. A tune read/write should take about a minute (never really timed it, but it's quick). Full read and write are about 15 minutes give or take. Oddly enough I found full writes are faster on the car rather than on the bench.

Automatically corrects all checksums and generates a valid RSA signature. This means the DME will attempt to execute whatever you send to it - so be careful making program writes. If you send it bad code, the DME will not be recoverable without a BDM tool. A full backup is strongly recommended before you do anything.

I've tested the application a fair bit, and it's fairly reliable. Very rarely the DME will kinda get stuck and refuse to grant security access - power cycling fixes that. That said, with more people using the app, I'm sure you guys will find bugs that I never would have imagined. The nice thing is this app is open source, so you can fix and improve it yourselves even if I'm too busy.

Usual disclaimers apply. The app can render your DME unbootable, flashing bad data might cause your car to behave unpredictably, etc. I'm not responsible for anything that happens either directly or indirectly as a result of this application.

Without further ado:

# MS45 Flasher
Tool to read and flash the MS45 DME. Can read/write full and partial binaries from the MS45.0 and MS45.1. It will automatically correct checksums and sign files that are flashed to the DME.


### Prerequisites
This application uses .Net Framework 4.5.2

Any INPA-compatible OBDII cable should work with this application. Make sure your cable latency is set to 1ms

You will need EdiabasLib.dll to compile and run this application.
The application assumes you have an ediabas installation in the default directory along with E46, E60, E65, E83, or E85 daten files.
If you don't have / want Ediabas installed, you will need to find a copy of MS450DS0.prg or 10MDS45.prg, and set the .config file to reflect the directory and filename of those files.
Most of my testing has been with MS450DS0.prg, so I recommend using that.


### Usage
Change the settings as necessary in the 'MS45 Flasher.exe.config' file. 
Default port is COM1, default sgbd directory is C:\Ediabas\ECU, and default sgbd is D_Motor.GRP (should automatically resolve to MS450DS0.prg if connected to an MS45 DME)



##### Identify your DME
Start the application, connect your interface to your OBDII port, and click "Ident DME"
If successful, the application should autopopulate some information from your DME

##### Reading your DME
For the tune, simply click "Read DME". 

If you would like to backup your full flash, check the "full binary" checkbox before clicking "Read DME"
A full backup will result in two files. The _Flash file is the external flash of your DME, and the _mpc file contains the data that's internal to the CPU. You need both of these

Save the file(s) whereever you like

##### Flashing your DME
It is *highly recommended* you make a full backup before you flash your DME

To flash a tune: 
* Click "Load File"
* Open the tune you'd like to flash
* Click "Flash Tune". 

If successful, your DME should reboot and the application status should reflect "Flash Successful"

To flash a full binary: 
* Check the "Full Binary" checkbox
* Click "Load File" and open the file that contains the external flash you'd like to use
* Click "Load File 2 (MPC)" and open the file that contains the mpc flash you'd like to use
* Click "Flash Program"
* **NOTE**: If the files do not match, you can render your DME unbootable. The application does do some basic checking, but it may not be fool proof

If the program version you flashed is different than what was on there before, you will also have to flash a tune. You can simply click "Flash Tune" to use the one embedded within the full file, or you can uncheck the checkbox and load an appropriate tune of your choice. 


## Built using

* [EdiabasLib](https://github.com/uholeschak/ediabaslib) - Used to communicate with the DME

## Acknowledgments

* Hassmaschine has been a tremendous help in disassembling the DME and understanding the how the code generally works. I likely never would have done much with the MS45 without his help
* See also the list of [contributors](https://github.com/terraphantm/MS45-Flasher/contributors) who participated / will participate in this project.


If this application has been useful for you and you would like to go a bit further with tuning, please consider checking out [bimmerlabs](https://www.bimmerlabs.com). The site is still growing, but our goal is to allow full control of most BMW DMEs. 

## License

This project is licensed under The GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details

## Disclaimer: 
This program is inherently invasive, and can render your DME unbootable and your car undriveable. Care must be taken when using this application. In no respect shall the authors or contributors incur any liability for any damages, including, but limited to, direct, indirect, special, or consequential damages arising out of, resulting from, or any way connected to the use of the application, whether or not based upon warranty, contract, tort, or otherwise; whether or not injury was sustained by persons or property or otherwise; and whether or not loss was sustained from, or arose out of, the results of, the item, or any services that may be provided by the authors and contributors.
