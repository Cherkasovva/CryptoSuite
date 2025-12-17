namespace NumberTheory
{
    public class StatelessNumberTheoryService
    {
        public LegendreService Legendre { get; } = new LegendreService();
        public JacobiService Jacobi { get; } = new JacobiService();
        public GcdService Gcd { get; } = new GcdService();
        public ExtendedGcdService ExtendedGcd { get; } = new ExtendedGcdService();
        public ModPowService ModPow { get; } = new ModPowService();
    }
}