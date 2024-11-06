using RAIDDetection;
using System;
using FTPMDetection;
class Program
{
    static void Main()
    {
        

        //Raid raid = new Raid();
        FtpmPoc ft = new FtpmPoc();
        ft.getTPMInfo2();
    }
    
}