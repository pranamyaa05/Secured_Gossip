import CreateSecret from './CreateSecret.jsx';
import ViewSecret from './ViewSecret.jsx';

function App() {
  const isViewRoute = window.location.hash.startsWith('#/view/');

  return isViewRoute ? <ViewSecret /> : <CreateSecret />;
}

export default App;
