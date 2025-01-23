package scraper

import (
	"fmt"

	"github.com/gocolly/colly"
)

func GetScrapeData(url string, domain string) {
	c := colly.NewCollector(
		colly.AllowedDomains(domain),
	)

	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		link := e.Attr("href")
		fmt.Printf("Link found: %q -> %s\n", e.Text, link)
	})
}
