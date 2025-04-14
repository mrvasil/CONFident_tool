/*!
 * Color mode toggler for Bootstrap's docs (https://getbootstrap.com/)
 * Copyright 2011-2024 The Bootstrap Authors
 * Licensed under the Creative Commons Attribution 3.0 Unported License.
 */

(() => {
  'use strict'

  const getStoredTheme = () => localStorage.getItem('theme')
  const setStoredTheme = theme => localStorage.setItem('theme', theme)

  const getPreferredTheme = () => {
    const storedTheme = getStoredTheme()
    if (storedTheme) {
      return storedTheme
    }

    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  }

  const setTheme = theme => {
    if (theme === 'auto') {
      document.documentElement.setAttribute('data-bs-theme', (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'))
    } else {
      document.documentElement.setAttribute('data-bs-theme', theme)
    }
  }

  setTheme(getPreferredTheme())

  const showActiveTheme = (theme, focus = false) => {
    const themeSwitcher = document.querySelector('#theme-toggle')

    if (!themeSwitcher) {
      return
    }

    const themeSwitcherSun = themeSwitcher.querySelector('.bi-sun-fill')
    const themeSwitcherMoon = themeSwitcher.querySelector('.bi-moon-stars-fill')
    const activeThemeIcon = theme === 'dark' ? themeSwitcherMoon : themeSwitcherSun
    const inactiveThemeIcon = theme === 'dark' ? themeSwitcherSun : themeSwitcherMoon

    // Update button icon
    if(activeThemeIcon) activeThemeIcon.classList.remove('d-none');
    if(inactiveThemeIcon) inactiveThemeIcon.classList.add('d-none');

    // Update button aria-label
    const themeSwitcherLabel = `Toggle theme (${theme})`
    themeSwitcher.setAttribute('aria-label', themeSwitcherLabel)

    if (focus) {
      themeSwitcher.focus()
    }
  }

  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    const storedTheme = getStoredTheme()
    if (storedTheme !== 'light' && storedTheme !== 'dark') {
      setTheme(getPreferredTheme())
    }
  })

  window.addEventListener('DOMContentLoaded', () => {
    showActiveTheme(getPreferredTheme())

    const themeToggle = document.querySelector('#theme-toggle')
    if (themeToggle) {
        themeToggle.addEventListener('click', () => {
            const currentTheme = getStoredTheme() || getPreferredTheme()
            const newTheme = currentTheme === 'light' ? 'dark' : 'light'
            setStoredTheme(newTheme)
            setTheme(newTheme)
            showActiveTheme(newTheme, true)
        })
    }
  })
})() 