namespace SpawnDev.BlazorJS.Rally
{
    /// <summary>
    /// Signaler swarm stats for an info hash
    /// </summary>
    public class RallyPointStats
    {
        /// <summary>
        /// Signaler url
        /// </summary>
        public string SignalerUrl { get; set; } = "";
        /// <summary>
        /// The hash stats
        /// </summary>
        public int CompletePeers { get; set; }
        /// <summary>
        /// The hash stats
        /// </summary>
        public int IncompletePeers { get; set; }
        /// <summary>
        /// The hash stats
        /// </summary>
        public int Interval { get; set; }
        /// <summary>
        /// When the hash info was last updated
        /// </summary>
        public DateTime LastUpdated { get; set; } = DateTime.MinValue;
        /// <summary>
        /// The current state on this signaler.<br/>
        /// The default state is stopped.<br/>
        /// - stopped<br/>
        /// - started<br/>
        /// - completed<br/>
        /// </summary>
        public string State { get; set; } = "stopped";
        /// <summary>
        /// Returns true if in the swarm
        /// </summary>
        public bool InSwarm { get; set; }
        /// <summary>
        /// Returns true if in the swarm
        /// </summary>
        public bool CompletedSent { get; set; }
    }
}
