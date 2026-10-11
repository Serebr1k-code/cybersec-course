<script setup>
import { useTreeStore } from '../stores/tree'
import { onMounted } from 'vue'

const tree = useTreeStore()
onMounted(() => tree.load())
</script>

<template>
  <div class="about-view">
    <h1>CTF Learning Tree</h1>
    <p class="lead">
      Интерактивное дерево обучения для подготовки к CTF-соревнованиям, bug bounty и пентесту.
      Каждая категория — отдельная ветка, уроки связаны в граф «от основ к сложному»,
      а прогресс чтения отображается прямо на дереве.
    </p>

    <section class="card block">
      <h2>Как это работает</h2>
      <ul>
        <li><b>Дерево знаний</b> — уроки соединены связями <code>parent</code>, образуя ветки и ответвления.</li>
        <li><b>Прогресс по времени чтения</b> — при чтении засекается время на каждом разделе. Когда раздел прочитан, его доля закрашивается <span class="g">зелёным</span> на квадратике дерева (слева направо).</li>
        <li><b>Квиз</b> — в конце урока проверка знаний; правильные ответы дают XP.</li>
        <li><b>XP, уровень и серия</b> — очки за прочитанные разделы, пройденные уроки и идеальные квизы; серия — дни подряд.</li>
        <li><b>Заметки</b> — личный конспект к каждому уроку, сохраняется автоматически.</li>
        <li><b>Поиск</b> — по заголовкам, тегам и содержимому уроков.</li>
        <li><b>Экспорт/импорт</b> — резервная копия прогресса.</li>
      </ul>
    </section>

    <section class="card block">
      <h2>Категории</h2>
      <div class="cats">
        <div v-for="c in tree.categories" :key="c.slug" class="cat">
          <span class="ci" :style="{ borderColor: c.color }">{{ c.icon }}</span>
          <div>
            <b>{{ c.name }}</b>
            <p class="muted">{{ c.description }}</p>
          </div>
          <span class="cnt chip">{{ c.count }} уроков</span>
        </div>
      </div>
    </section>

    <section class="card block">
      <h2>Технологии</h2>
      <p class="muted">
        Бэкенд — Go (стандартная библиотека, HTTP API + раздача SPA). Фронтенд — Vue 3 + Vite.
        Контент — markdown-файлы с YAML-фронтматтером в каталоге <code>content/&lt;категория&gt;/</code>.
        Дерево строится автоматически из связей <code>parent</code>, поэтому его легко расширять:
        достаточно добавить новый markdown-файл.
      </p>
    </section>
  </div>
</template>

<style scoped>
.about-view { max-width: 900px; margin: 0 auto; padding: 28px 24px 80px; }
h1 { font-size: 1.8rem; margin: 0 0 10px; }
.lead { font-size: 15.5px; color: var(--text-soft); margin-bottom: 26px; line-height: 1.7; }
.block { padding: 22px 24px; margin-bottom: 18px; }
h2 { font-size: 1.15rem; margin: 0 0 14px; }
ul { margin: 0; padding-left: 20px; }
li { margin: 9px 0; color: var(--text-soft); line-height: 1.6; }
code { font-family: var(--mono); font-size: .88em; background: var(--panel-3); border: 1px solid var(--border-soft); border-radius: 4px; padding: 1px 6px; color: #a5e6ff; }
.g { color: var(--green); font-weight: 600; }
.cats { display: flex; flex-direction: column; gap: 10px; }
.cat { display: flex; align-items: center; gap: 13px; }
.cat > div { min-width: 0; }         /* длинные описания переносятся, не растягивают */
.ci { width: 36px; height: 36px; border-radius: 9px; display: grid; place-items: center; border: 1px solid var(--border-strong); font-size: 18px; flex: none; }
.cat b { font-size: 14px; }
.cat p { margin: 2px 0 0; font-size: 12.5px; }
.cnt { margin-left: auto; white-space: nowrap; }

@media (max-width: 560px) {
  .about-view { padding: 18px 14px 72px; }
  h1 { font-size: 1.5rem; }
  .lead { font-size: 15px; margin-bottom: 20px; }
  .block { padding: 18px 16px; margin-bottom: 14px; }
  .cat { gap: 10px; align-items: flex-start; }
  .cnt { margin-left: auto; }
}
</style>
