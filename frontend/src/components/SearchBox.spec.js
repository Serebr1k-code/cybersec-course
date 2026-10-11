import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { nextTick } from 'vue'
import SearchBox from './SearchBox.vue'
import { api } from '../api/client'

const { push } = vi.hoisted(() => ({ push: vi.fn() }))

vi.mock('vue-router', () => ({
  useRouter: () => ({ push })
}))

vi.mock('../api/client', () => ({
  api: { search: vi.fn() }
}))

const RESULTS = [
  { id: 'web-sqli', title: 'SQLi', difficulty: 'easy', category: 'web', summary: 's1' },
  { id: 'web-xss', title: 'XSS', difficulty: 'medium', category: 'web', summary: 's2' }
]

describe('components/SearchBox.vue', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.clearAllMocks()
    api.search.mockResolvedValue({ results: RESULTS })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  async function typeAndRun(wrapper, value) {
    await wrapper.find('input').setValue(value)
    await vi.advanceTimersByTimeAsync(220)
    await nextTick()
  }

  it('debounces the search request', async () => {
    const wrapper = mount(SearchBox)
    const input = wrapper.find('input')
    await input.setValue('s')
    await input.setValue('sq')
    await input.setValue('sql')
    expect(api.search).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(220)
    await nextTick()
    expect(api.search).toHaveBeenCalledTimes(1)
    expect(api.search).toHaveBeenCalledWith('sql')
  })

  it('renders the result dropdown after a search', async () => {
    const wrapper = mount(SearchBox)
    await typeAndRun(wrapper, 'web')
    expect(wrapper.find('.drop').exists()).toBe(true)
    const items = wrapper.findAll('.item')
    expect(items.length).toBe(2)
    expect(items[0].text()).toContain('SQLi')
    expect(items[0].text()).toContain('web')
  })

  it('does not search for a blank query', async () => {
    const wrapper = mount(SearchBox)
    await wrapper.find('input').setValue('   ')
    await vi.advanceTimersByTimeAsync(300)
    expect(api.search).not.toHaveBeenCalled()
    expect(wrapper.find('.drop').exists()).toBe(false)
  })

  it('clears results when the query is emptied', async () => {
    const wrapper = mount(SearchBox)
    await typeAndRun(wrapper, 'web')
    expect(wrapper.findAll('.item').length).toBe(2)
    await wrapper.find('input').setValue('')
    await nextTick()
    expect(wrapper.find('.drop').exists()).toBe(false)
  })

  it('shows an empty-state when nothing matches', async () => {
    api.search.mockResolvedValue({ results: [] })
    const wrapper = mount(SearchBox)
    await typeAndRun(wrapper, 'zzzz')
    expect(wrapper.find('.empty').text()).toContain('Ничего не найдено')
  })

  it('does not crash when the search API fails', async () => {
    api.search.mockRejectedValue(new Error('down'))
    const wrapper = mount(SearchBox)
    await typeAndRun(wrapper, 'web')
    expect(wrapper.findAll('.item').length).toBe(0)
  })

  it('navigates the results with the arrow keys and opens with Enter', async () => {
    const wrapper = mount(SearchBox)
    await typeAndRun(wrapper, 'web')
    const input = wrapper.find('input')
    // first item active by default
    expect(wrapper.findAll('.item')[0].classes()).toContain('active')
    await input.trigger('keydown', { key: 'ArrowDown' })
    expect(wrapper.findAll('.item')[1].classes()).toContain('active')
    await input.trigger('keydown', { key: 'ArrowDown' }) // wraps to 0
    expect(wrapper.findAll('.item')[0].classes()).toContain('active')
    await input.trigger('keydown', { key: 'ArrowUp' }) // wraps back to 1
    expect(wrapper.findAll('.item')[1].classes()).toContain('active')
    await input.trigger('keydown', { key: 'Enter' })
    expect(push).toHaveBeenCalledWith('/lesson/web-xss')
  })

  it('routes to the first result on Enter without navigation', async () => {
    const wrapper = mount(SearchBox)
    await typeAndRun(wrapper, 'web')
    await wrapper.find('input').trigger('keydown', { key: 'Enter' })
    expect(push).toHaveBeenCalledWith('/lesson/web-sqli')
  })

  it('closes the dropdown on Escape', async () => {
    const wrapper = mount(SearchBox)
    await typeAndRun(wrapper, 'web')
    expect(wrapper.find('.drop').exists()).toBe(true)
    await wrapper.find('input').trigger('keydown', { key: 'Escape' })
    expect(wrapper.find('.drop').exists()).toBe(false)
  })

  it('routes when a result is clicked', async () => {
    const wrapper = mount(SearchBox)
    await typeAndRun(wrapper, 'web')
    await wrapper.findAll('.item')[1].trigger('mousedown')
    expect(push).toHaveBeenCalledWith('/lesson/web-xss')
    // clicking also closes the dropdown and clears the query
    expect(wrapper.find('.drop').exists()).toBe(false)
    expect(wrapper.find('input').element.value).toBe('')
  })

  it('highlights the hovered item', async () => {
    const wrapper = mount(SearchBox)
    await typeAndRun(wrapper, 'web')
    await wrapper.findAll('.item')[1].trigger('mouseenter')
    expect(wrapper.findAll('.item')[1].classes()).toContain('active')
  })

  it('ignores arrow keys when the dropdown is closed', async () => {
    const wrapper = mount(SearchBox)
    const input = wrapper.find('input')
    await input.trigger('keydown', { key: 'ArrowDown' })
    await input.trigger('keydown', { key: 'Enter' })
    expect(push).not.toHaveBeenCalled()
  })
})
