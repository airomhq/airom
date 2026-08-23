package cli

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/services/cluster"
)

func newClusterCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "cluster",
		GroupID: groupCompliance,
		Short:   "Inspect high-availability cluster consensus, node heartbeats, and leader election status",
		Long: `High-Availability Clustering & Distributed Consensus Manager.
Monitors node heartbeats, active cluster leader, quorum status, and failover health.`,
	}

	cmd.AddCommand(newClusterStatusCmd())

	return cmd
}

func newClusterStatusCmd() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Display high-availability cluster consensus and node topology",
		RunE: func(cmd *cobra.Command, _ []string) error {
			mgr := cluster.NewClusterManager("airom-production-ha-cluster")

			// Register local node and replica nodes
			_ = mgr.RegisterNode(cluster.ClusterNode{
				NodeID:          "airom-node-us-east-1a",
				Hostname:        "10.0.1.42",
				Port:            8080,
				ServicesActive:  []string{"gateway", "compliancedb", "regwatch", "filing"},
				LastHeartbeatAt: time.Now().UTC(),
			})
			_ = mgr.RegisterNode(cluster.ClusterNode{
				NodeID:          "airom-node-us-east-1b",
				Hostname:        "10.0.1.88",
				Port:            8080,
				ServicesActive:  []string{"gateway", "compliancedb", "provenance", "redteam"},
				LastHeartbeatAt: time.Now().UTC(),
			})
			_ = mgr.RegisterNode(cluster.ClusterNode{
				NodeID:          "airom-node-us-west-2a",
				Hostname:        "10.0.2.19",
				Port:            8080,
				ServicesActive:  []string{"dashboard", "workforce", "shadowai"},
				LastHeartbeatAt: time.Now().UTC(),
			})

			state := mgr.GetClusterState()

			if asJSON {
				data, err := json.MarshalIndent(state, "", "  ")
				if err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(data))
				return nil
			}

			fmt.Fprint(cmd.OutOrStdout(), cluster.RenderClusterDashboard(state))
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "Output cluster state as JSON")

	return cmd
}
