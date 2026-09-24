import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

/**
 * Automated accessibility checks (WCAG 2.1 A/AA) on the two views an analyst
 * actually uses. Automated scanning does not replace manual testing, but it
 * catches contrast, labelling and landmark regressions.
 */
async function scan(page) {
  return new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
    .analyze();
}

test("alert queue has no accessibility violations", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("table")).toBeVisible();

  const results = await scan(page);
  expect(results.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
});

test("alert detail has no accessibility violations", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("table")).toBeVisible();
  await page.locator("table tbody tr").first().getByRole("button").click();
  await expect(page.getByRole("complementary", { name: "Alert details" })).toBeVisible();

  const results = await scan(page);
  expect(results.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
});

test("every form control has an accessible name", async ({ page }) => {
  await page.goto("/");
  const controls = page.locator("input, select, button");
  const count = await controls.count();
  for (let i = 0; i < count; i += 1) {
    const control = controls.nth(i);
    if (!(await control.isVisible())) continue;
    const name = await control.evaluate((element) => {
      const label = element.labels?.[0]?.textContent;
      return (element.getAttribute("aria-label") || label || element.textContent || "").trim();
    });
    expect(name, `control #${i} has no accessible name`).not.toBe("");
  }
});
