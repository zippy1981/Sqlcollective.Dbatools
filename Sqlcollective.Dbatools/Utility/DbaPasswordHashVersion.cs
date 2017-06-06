using System;
using System.Collections.Generic;
using System.Linq;
using Sqlcollective.Dbatools.Utility;

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

public static class DbaToolsExtensionMethods
{
    /// <summary>
    /// Gets a little endian byte array representation of the version code.
    /// </summary>
    /// <returns>either <c>0x0100</c> for SQL 2000-2008 or <c>0x0200</c> for SQL 2012-SQL 2017</returns>
    /// <exception cref="ArgumentOutOfRangeException"></exception>
    /// <remarks>Originally written because I didn't take endianness into account</remarks>
    public static byte[] GetBytes(this DbaPasswordHashVersion version)
    {
        switch (version)
        {
            case DbaPasswordHashVersion.Sql2000:
                return new byte[] { 1, 0 };
            case DbaPasswordHashVersion.Sql2012:
                return new byte[] { 2, 0 };
            default:
                throw new ArgumentOutOfRangeException(nameof(version), version, null);
        }
    }

    //TODO: Replace with a better answer from here: https://gist.github.com/aelij/b62d149e1a85c3edfad7598e9c2f12cb
    public static bool EqualsArray<T>(this IList<T> a, IList<T> b)
    {
        if (a.Count != b.Count) return false;
        return !a.Where((t, i) => !t.Equals(b[i])).Any();
    }
}