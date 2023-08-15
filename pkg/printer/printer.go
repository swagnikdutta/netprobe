package printer

type Printer interface {
	PrintTableView(data [][]string, headers []string)
}
