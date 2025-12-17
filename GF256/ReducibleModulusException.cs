using System;

namespace GF256
{
    public class ReducibleModulusException : Exception
    {
        public ReducibleModulusException() { }
        public ReducibleModulusException(string message) : base(message) { }
    }
}