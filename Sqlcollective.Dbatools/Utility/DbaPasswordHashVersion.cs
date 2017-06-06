namespace Sqlcollective.Dbatools.Utility
{
    /// <remarks>
    /// The word in a SQL Server password hash is a LITTLE ENDIAN version number of the password. Before 2012 it was 
    /// 0x0100 or 1. After 2012 it is 0x0200 or 2.
    /// </remarks>>
    public enum DbaPasswordHashVersion : ushort {
        Sql2000 = 1,
        Sql2005 = 1,
        Sql2008 = 1,
        Sql2012 = 2,
        Sql2016 = 2,
        Sql2017 = 2,
    }
}