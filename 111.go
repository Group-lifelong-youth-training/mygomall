package 青训营

func getRow(rowIndex int) []int {
	if rowIndex == 0 {
		return []int{1}
	} else {
		result := []int{1, 1}
		qw := []int{1}
		for i := 2; i <= rowIndex; i++ {
			for j := 0; j < len(result)-1; j++ {
				qw = append(qw, (result[j] + result[j+1]))
			}
			qw = append(qw, 1)
			result = qw
			qw = []int{1}
		}
		return result
	}

}
