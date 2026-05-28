use ratatui::{
    layout::{Constraint, Direction, Layout},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

pub enum TuiScreen {
    Dashboard,
    Interfaces,
    Firewall,
    Qos,
    Config,
    Logs,
}

pub struct TuiApp {
    pub screen: TuiScreen,
    pub status_message: String,
    pub running: bool,
}

impl Default for TuiApp {
    fn default() -> Self {
        Self {
            screen: TuiScreen::Dashboard,
            status_message: String::new(),
            running: true,
        }
    }
}

impl TuiApp {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn draw(&self, frame: &mut Frame) {
        let areas = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(1),
                Constraint::Length(3),
            ])
            .split(frame.area());

        let header = Paragraph::new("PungliOS — ISP Management Platform")
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(header, areas[0]);

        match self.screen {
            TuiScreen::Dashboard => self.draw_dashboard(frame, areas[1]),
            TuiScreen::Interfaces => self.draw_interfaces(frame, areas[1]),
            TuiScreen::Firewall => self.draw_firewall(frame, areas[1]),
            TuiScreen::Qos => self.draw_qos(frame, areas[1]),
            TuiScreen::Config => self.draw_config(frame, areas[1]),
            TuiScreen::Logs => self.draw_logs(frame, areas[1]),
        }

        let footer = Paragraph::new(format!("Status: {}", self.status_message))
            .block(Block::default().borders(Borders::ALL));
        frame.render_widget(footer, areas[2]);
    }

    fn draw_dashboard(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let items = vec![
            ListItem::new("Interfaces — 0 active"),
            ListItem::new("Firewall — 0 zones, 0 rules"),
            ListItem::new("QoS — 0 classes"),
            ListItem::new("Conntrack — 0 entries"),
            ListItem::new("System — CPU: 0%, Memory: 0 MB"),
        ];
        let list = List::new(items).block(Block::default().title("Dashboard").borders(Borders::ALL));
        frame.render_widget(list, area);
    }

    fn draw_interfaces(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let items = vec![ListItem::new("No interfaces configured")];
        let list = List::new(items).block(Block::default().title("Interfaces").borders(Borders::ALL));
        frame.render_widget(list, area);
    }

    fn draw_firewall(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let items = vec![ListItem::new("No firewall rules")];
        let list = List::new(items).block(Block::default().title("Firewall").borders(Borders::ALL));
        frame.render_widget(list, area);
    }

    fn draw_qos(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let items = vec![ListItem::new("No QoS classes")];
        let list = List::new(items).block(Block::default().title("QoS").borders(Borders::ALL));
        frame.render_widget(list, area);
    }

    fn draw_config(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let items = vec![ListItem::new("No config loaded")];
        let list = List::new(items).block(Block::default().title("Config").borders(Borders::ALL));
        frame.render_widget(list, area);
    }

    fn draw_logs(&self, frame: &mut Frame, area: ratatui::layout::Rect) {
        let items = vec![ListItem::new("No logs")];
        let list = List::new(items).block(Block::default().title("System Logs").borders(Borders::ALL));
        frame.render_widget(list, area);
    }
}
