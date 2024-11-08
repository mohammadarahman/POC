using System;
using System.Threading.Tasks;
using FTPMDetection;
class Program
{
    static async Task Main()
    {
        

        //Raid raid = new Raid();
        //raid.GetRaidControllersAndDiskDrives();
        FtpmPoc ft = new FtpmPoc();
        ft.getTPMInfo1();
        
    }
    
}